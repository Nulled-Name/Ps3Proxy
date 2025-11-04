import http.server
import socketserver
import urllib.request
import urllib.parse
import socket
import threading
import os
import time
import select
import logging
from datetime import datetime
import ipaddress


class RobustPS3ProxyHandler(http.server.BaseHTTPRequestHandler):
    """Proxy HTTP robusto que maneja mejor las conexiones"""
    
    # CONFIGURACIÓN
    PUP_FILE = "HFW_4.92.1_PS3UPDAT.PUP"
    OFFER_VERSION = "4.93"
    
    # Timeouts (en segundos)
    CONNECT_TIMEOUT = 10
    RESPONSE_TIMEOUT = 30
    TUNNEL_TIMEOUT = 30
    
    # Configurar logging
    logger = logging.getLogger("ps3proxy")
    
    # Mapeo completo de regiones a códigos Dest
    REGION_DEST_MAP = {
        '/us/': '84',      # US
        '/eu/': '85',      # EU
        '/jp/': '83',      # JP
        '/mx/': '88',      # MX
        '/br/': '8F',      # BR
        '/de/': '85',      # DE (usa EU)
        '/fr/': '85',      # FR (usa EU)
        '/uk/': '87',      # UK
        '/kr/': '86',      # KR
        '/tw/': '8B',      # TW
        '/cn/': '8D',      # CN
        '/ru/': '8C',      # RU
        '/au/': '89',      # AU/NZ
        '/nz/': '89',      # AU/NZ
        '/sa/': '8A',      # South Asia
    }
    
    # Nombres completos de regiones para mostrar
    REGION_NAMES = {
        '83': 'Japan (JP)',
        '84': 'United States (US)',
        '85': 'Europe (EU)',
        '86': 'Korea (KR)',
        '87': 'United Kingdom (UK)',
        '88': 'Mexico (MX)',
        '89': 'Australia/New Zealand (AU/NZ)',
        '8A': 'South Asia (SA)',
        '8B': 'Taiwan (TW)',
        '8C': 'Russia (RU)',
        '8D': 'China (CN)',
        '8F': 'Brazil (BR)',
    }
    
    # Patrones para detectar automáticamente actualizaciones de PS3
    PS3_UPDATE_PATTERNS = [
        '.ps3.update.playstation.net/update/ps3/list/',
        'ps3-updatelist.txt',
    ]
    
    # Headers que deben ser filtrados en reenvío
    FILTERED_REQUEST_HEADERS = {
        'host', 'proxy-connection', 'connection', 
        'accept-encoding', 'keep-alive'
    }
    
    # Headers que deben ser filtrados en respuestas
    FILTERED_RESPONSE_HEADERS = {
        'transfer-encoding', 'connection', 'keep-alive'
    }
    
    def log_message(self, format, *args):
        """Log personalizado con timestamp usando logging"""
        client_ip = self.client_address[0]
        self.logger.info(f"{client_ip} - {format % args}")
    
    def do_GET(self):
        self._handle_request('GET')
    
    def do_HEAD(self):
        self._handle_request('HEAD')
    
    def do_POST(self):
        self._handle_request('POST')
    
    def do_CONNECT(self):
        """Maneja conexiones HTTPS con soporte IPv6"""
        self.logger.info(f"CONNECT para HTTPS: {self.path}")
        try:
            # Parsear host y puerto con soporte IPv6
            host, port = self._parse_connect_host_port(self.path)
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as remote_socket:
                remote_socket.settimeout(self.CONNECT_TIMEOUT)
                remote_socket.connect((host, port))
                
                self.send_response(200, 'Connection Established')
                self.end_headers()
                
                self._tunnel_sockets_improved(self.connection, remote_socket)
                
        except Exception as e:
            self.logger.error(f"Error CONNECT: {e}")
            self.send_error(502, f"HTTPS Error: {e}")
    
    def _parse_connect_host_port(self, connect_path):
        """Parsea host:port con soporte IPv6"""
        try:
            # Manejar IPv6 [host]:port
            if connect_path.startswith('['):
                # IPv6: [::1]:443
                host_end = connect_path.find(']')
                if host_end != -1:
                    host = connect_path[1:host_end]
                    port_str = connect_path[host_end+2:]  # saltar ']:'
                    port = int(port_str) if port_str else 443
                    return host, port
            else:
                # IPv4: host:port
                if ':' in connect_path:
                    host, port_str = connect_path.split(':', 1)
                    port = int(port_str) if port_str else 443
                    return host, port
                else:
                    return connect_path, 443
        except Exception as e:
            self.logger.error(f"Error parsing CONNECT: {e}")
            raise ValueError(f"Invalid CONNECT target: {connect_path}")
    
    def _handle_request(self, method):
        """Maneja todas las peticiones HTTP"""
        start_time = time.time()
        
        self.logger.info(f"{method} {self.path}")
        
        try:
            # Verificar si es petición PS3 usando detección automática
            if self._is_ps3_update_request():
                self.logger.info("INTERCEPTANDO (PS3 Update)")
                self._handle_ps3_update(method)
            else:
                self.logger.info("REENVIANDO (Tráfico normal)")
                self._forward_http_request(method)
        
        except Exception as e:
            self.logger.error(f"Error handling request: {e}")
            self.send_error(500, f"Internal Server Error: {e}")
        
        elapsed = time.time() - start_time
        self.logger.info(f"Tiempo total: {elapsed:.2f}s")
    
    def _is_ps3_update_request(self):
        """
        Detecta automáticamente peticiones de actualización de PS3
        """
        url = self.path.lower()
        host = self.headers.get('Host', '').lower()
        
        # Detectar por patrones específicos de PS3
        for pattern in self.PS3_UPDATE_PATTERNS:
            if pattern in url or pattern in host:
                self.logger.info(f"Patrón detectado: {pattern}")
                return True
        
        # Detectar por User-Agent de PS3
        user_agent = self.headers.get('User-Agent', '').lower()
        if 'ps3' in user_agent and 'update' in user_agent:
            self.logger.info("User-Agent PS3 detectado")
            return True
        
        # Detectar por estructura de URL típica de PS3
        if self._has_ps3_url_structure(url, host):
            return True
            
        return False
    
    def _has_ps3_url_structure(self, url, host):
        """Detecta estructura típica de URLs de actualización PS3"""
        region_patterns = list(self.REGION_DEST_MAP.keys())
        
        # Si la URL tiene estructura /update/ps3/list/[región]/ps3-updatelist.txt
        if '/update/ps3/list/' in url and any(region in url for region in region_patterns):
            self.logger.info("Estructura regional PS3 detectada")
            return True
        
        # Si el host contiene 'update' y la URL contiene 'ps3'
        if 'update' in host and 'ps3' in url:
            self.logger.info("Host de update con URL PS3 detectado")
            return True
            
        # Si es una petición a un archivo PUP desde cualquier dominio
        if url.endswith('.pup') and ('update' in url or 'ps3' in url):
            self.logger.info("Archivo PUP detectado")
            return True
            
        return False
    
    def _handle_ps3_update(self, method):
        """Maneja las actualizaciones de PS3"""
        try:
            # Lista de actualizaciones - cualquier dominio que cumpla los patrones
            if 'ps3-updatelist.txt' in self.path.lower():
                self._serve_update_list()
            
            # Archivo PUP - cualquier dominio
            elif 'ps3updat.pup' in self.path.lower():
                self._serve_pup_file(method)
            
            # Otras peticiones PS3 - reenviar
            else:
                self._forward_to_sony(method)
                
        except Exception as e:
            self.logger.error(f"Error PS3: {e}")
            self.send_error(500, f"Error: {e}")
    
    def _serve_update_list(self):
        """Sirve la lista de actualizaciones personalizada con Dest correcto por región"""
        version_num = self.OFFER_VERSION.replace('.', '')
        local_ip = self._get_local_ip()
        
        # Extraer región y código Dest
        region_info = self._extract_region_and_dest()
        region_name = region_info['region']
        dest_code = region_info['dest']
        
        # Para China (CN) el formato es diferente
        if dest_code == '8D':  # China
            update_list = f"""# {region_name}
Dest={dest_code};ImageVersion=00000000;SystemSoftwareVersion=0.0000;CDN=http://{local_ip}:{self.server.server_port}/PS3UPDAT.PUP;CDN_Timeout=30;"""
        else:
            # Formato estándar para otras regiones
            update_list = f"""# {region_name}
Dest={dest_code};CompatibleSystemSoftwareVersion=4.9200-;
Dest={dest_code};ImageVersion={version_num}00;SystemSoftwareVersion={version_num}00;CDN=http://{local_ip}:{self.server.server_port}/PS3UPDAT.PUP;CDN_Timeout=30;"""
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=UTF-8')
        self.send_header('Content-Length', str(len(update_list)))
        self.send_header('Server', 'Apache/2.4.41 (Ubuntu)')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(update_list.encode())
        
        self.logger.info(f"Lista servida - Versión: {self.OFFER_VERSION}, Región: {region_name}, Dest: {dest_code}")
    
    def _extract_region_and_dest(self):
        """
        Extrae la región y el código Dest correspondiente de la URL
        Retorna: {'region': 'Nombre región', 'dest': 'código'}
        """
        url = self.path.lower()
        
        # Buscar patrón de región en la URL
        for url_pattern, dest_code in self.REGION_DEST_MAP.items():
            if url_pattern in url:
                region_name = self.REGION_NAMES.get(dest_code, f"Region_{dest_code}")
                return {
                    'region': region_name,
                    'dest': dest_code
                }
        
        # Si no se encuentra región específica, usar MX como default
        self.logger.warning("Región no detectada, usando MX como default")
        return {
            'region': 'Mexico (MX)',
            'dest': '88'
        }
    
    def _serve_pup_file(self, method):
        """Sirve el archivo PUP local con validaciones"""
        self.logger.info(f"Sirviendo: {self.PUP_FILE}")
        
        # Validar que el archivo existe y es accesible
        pup_path = os.path.abspath(self.PUP_FILE)
        if not os.path.exists(pup_path):
            self.logger.error(f"PUP no encontrado: {pup_path}")
            self.send_error(404, "PUP file not found")
            return
        
        try:
            file_size = os.path.getsize(pup_path)
            
            # Headers comunes
            headers = {
                'Content-Type': 'application/octet-stream',
                'Content-Length': str(file_size),
                'Content-Disposition': 'attachment; filename="PS3UPDAT.PUP"',
                'Server': 'Apache/2.4.41 (Ubuntu)',
                'Accept-Ranges': 'bytes',
                'Connection': 'close'
            }
            
            # Para HEAD - solo headers
            if method == 'HEAD':
                self.send_response(200)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.logger.info("HEAD respondido")
                return
            
            # Para GET - enviar archivo
            self.send_response(200)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            
            # Enviar archivo en chunks con manejo de errores
            self._send_file_safely(pup_path, file_size)
            
        except Exception as e:
            self.logger.error(f"Error sirviendo PUP: {e}")
            self.send_error(500, f"Error: {e}")
    
    def _send_file_safely(self, file_path, file_size):
        """Envía archivo de forma segura con manejo de errores"""
        sent_bytes = 0
        start_time = time.time()
        progress_interval = 10 * 1024 * 1024  # 10MB
        
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(32768)  # 32KB chunks
                    if not chunk:
                        break
                    
                    try:
                        self.wfile.write(chunk)
                        sent_bytes += len(chunk)
                        
                        # Mostrar progreso cada 10MB
                        if sent_bytes % progress_interval == 0:
                            mb_sent = sent_bytes // (1024 * 1024)
                            elapsed = time.time() - start_time
                            speed = (sent_bytes / 1024 / 1024) / elapsed if elapsed > 0 else 0
                            self.logger.info(f"Progreso: {mb_sent}MB ({speed:.1f} MB/s)")
                    
                    except (BrokenPipeError, ConnectionResetError) as e:
                        self.logger.warning(f"Cliente cerró la conexión: {e}")
                        break
                    except Exception as e:
                        self.logger.error(f"Error enviando chunk: {e}")
                        raise
            
            total_time = time.time() - start_time
            self.logger.info(f"PUP enviado: {sent_bytes}/{file_size} bytes en {total_time:.1f}s")
            
            if sent_bytes != file_size:
                self.logger.warning(f"Transferencia incompleta: {sent_bytes}/{file_size} bytes")
                
        except Exception as e:
            self.logger.error(f"Error en transferencia de archivo: {e}")
            raise
    
    def _forward_to_sony(self, method):
        """Reenvía peticiones PS3 a Sony"""
        try:
            # Construir URL completa de forma robusta
            url = self._build_target_url()
            if not url:
                self.send_error(400, "Invalid URL")
                return
            
            self.logger.info(f"Reenviando a Sony: {url}")
            
            # Headers limpios
            headers = self._get_clean_headers()
            
            # Realizar petición
            req = urllib.request.Request(url, method=method, headers=headers)
            with urllib.request.urlopen(req, timeout=self.RESPONSE_TIMEOUT) as response:
                # Enviar respuesta
                self.send_response(response.getcode())
                
                # Filtrar headers de respuesta
                for header, value in response.headers.items():
                    if header.lower() not in self.FILTERED_RESPONSE_HEADERS:
                        self.send_header(header, value)
                
                self.send_header('Connection', 'close')
                self.end_headers()
                
                # Enviar datos
                if method == 'GET':
                    self.wfile.write(response.read())
                
                self.logger.info(f"Reenvío exitoso: {response.getcode()}")
                
        except Exception as e:
            self.logger.error(f"Error reenviando a Sony: {e}")
            self.send_error(502, f"Error: {e}")
    
    def _forward_http_request(self, method):
        """Reenvía peticiones HTTP normales de forma robusta"""
        try:
            # Construir URL correcta
            url = self._build_target_url()
            if not url:
                self.send_error(400, "No Host header or invalid URL")
                return
            
            self.logger.info(f"Reenviando: {url}")
            
            # Headers limpios
            headers = self._get_clean_headers()
            
            # Manejar body para POST
            data = None
            if method == 'POST':
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    data = self.rfile.read(content_length)
            
            # Realizar petición con timeout
            req = urllib.request.Request(url, method=method, headers=headers, data=data)
            
            with urllib.request.urlopen(req, timeout=self.RESPONSE_TIMEOUT) as response:
                # Enviar respuesta al cliente
                self.send_response(response.getcode())
                
                # Filtrar headers problemáticos preservando content-encoding
                for header, value in response.headers.items():
                    header_lower = header.lower()
                    if header_lower not in self.FILTERED_RESPONSE_HEADERS:
                        self.send_header(header, value)
                
                self.end_headers()
                
                # Enviar contenido en chunks
                if method in ['GET', 'POST']:
                    while True:
                        chunk = response.read(8192)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                
                self.logger.info(f"Reenvío exitoso: {response.getcode()}")
                
        except urllib.error.URLError as e:
            self.logger.error(f"Error URL: {e}")
            self.send_error(502, f"Network Error: {e}")
        except socket.timeout:
            self.logger.error("Timeout en reenvío")
            self.send_error(504, "Gateway Timeout")
        except Exception as e:
            self.logger.error(f"Error reenviando: {e}")
            self.send_error(502, f"Proxy Error: {e}")
    
    def _build_target_url(self):
        """Construye URL target de forma robusta"""
        if self.path.startswith('http://'):
            return self.path
        
        host = self.headers.get('Host', '')
        if not host:
            return None
        
        # Normalizar host (quitar puerto si es necesario para URL)
        if ':' in host:
            host = host.split(':', 1)[0]
        
        return f"http://{host}{self.path}"
    
    def _get_clean_headers(self):
        """Limpia los headers para reenvío de forma consistente"""
        clean_headers = {}
        
        for key, value in self.headers.items():
            key_lower = key.lower()
            if key_lower not in self.FILTERED_REQUEST_HEADERS:
                clean_headers[key] = value
        
        # Headers importantes para compatibilidad
        if 'User-Agent' not in clean_headers:
            clean_headers['User-Agent'] = self.headers.get('User-Agent', 'Mozilla/5.0')
        if 'Accept' not in clean_headers:
            clean_headers['Accept'] = self.headers.get('Accept', '*/*')
        
        return clean_headers
    
    def _tunnel_sockets_improved(self, client_socket, remote_socket):
        """Establece tunnel para conexiones HTTPS mejorado"""
        sockets = [client_socket, remote_socket]
        
        try:
            for sock in sockets:
                sock.settimeout(self.TUNNEL_TIMEOUT)
            
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, self.TUNNEL_TIMEOUT)
                
                if exceptional:
                    break
                
                if not readable:
                    # Timeout, verificar si hay datos pendientes
                    continue
                
                for sock in readable:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            # Conexión cerrada
                            return
                        
                        target = remote_socket if sock is client_socket else client_socket
                        target.sendall(data)
                        
                    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError) as e:
                        self.logger.info(f"Tunnel error: {e}")
                        return
                        
        except select.error as e:
            self.logger.info(f"Select error in tunnel: {e}")
        finally:
            # Cierre seguro de sockets
            for sock in sockets:
                try:
                    sock.close()
                except:
                    pass
    
    def _get_local_ip(self):
        """Obtiene la IP local con múltiples métodos de fallback"""
        # Método 1: Conexión a DNS
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            pass
        
        # Método 2: Nombre de host
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            pass
        
        # Método 3: Fallback a localhost
        return "127.0.0.1"


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Servidor HTTP con soporte para múltiples hilos"""
    daemon_threads = True
    allow_reuse_address = True


def setup_logging():
    """Configura el sistema de logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    return logging.getLogger("ps3proxy")


def main():
    """Función principal"""
    logger = setup_logging()
    HOST = '0.0.0.0'
    PORT = 8080
    
    # Obtener IP local una vez
    local_ip = get_local_ip()
    
    print("🎮 PS3 HFW PROXY - ROBUSTO Y MEJORADO")
    print("=" * 50)
    print(f"📍 Proxy: http://{local_ip}:{PORT}")
    print(f"📁 PUP: {RobustPS3ProxyHandler.PUP_FILE}")
    print(f"🏷️  Versión: {RobustPS3ProxyHandler.OFFER_VERSION}")
    print()
    print("✅ MEJORAS IMPLEMENTADAS:")
    print("   • Logging robusto con timestamps")
    print("   • Soporte IPv6 en CONNECT")
    print("   • Manejo mejorado de errores")
    print("   • Filtrado consistente de headers")
    print("   • Transferencias de archivo seguras")
    print()
    print("🔧 CONFIGURACIÓN PS3:")
    print(f"   Proxy: {local_ip}:{PORT}")
    print()
    print("⏹️  Ctrl+C para detener")
    print("=" * 50)
    
    # Verificar archivo PUP
    pup_path = os.path.abspath(RobustPS3ProxyHandler.PUP_FILE)
    if not os.path.exists(pup_path):
        print(f"❌ ERROR: No se encuentra {pup_path}")
        print("💡 Coloca el archivo PUP en la misma carpeta")
        return
    
    size = os.path.getsize(pup_path)
    print(f"✅ PUP encontrado: {size} bytes ({size//1024//1024} MB)")
    
    try:
        # Crear servidor con soporte para hilos
        server = ThreadedHTTPServer((HOST, PORT), RobustPS3ProxyHandler)
        logger.info(f"Proxy iniciado en puerto {PORT}")
        print(f"\n🚀 Proxy iniciado en puerto {PORT}")
        print("📡 Esperando conexiones...")
        server.serve_forever()
        
    except KeyboardInterrupt:
        print("\n🛑 Proxy detenido por el usuario")
        logger.info("Proxy detenido por usuario")
    except Exception as e:
        logger.error(f"Error: {e}")
        print(f"❌ Error: {e}")


def get_local_ip():
    """Obtiene la IP local con fallbacks"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "127.0.0.1"


if __name__ == '__main__':
    main()