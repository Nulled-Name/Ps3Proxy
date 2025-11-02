import http.server
import socketserver
import urllib.request
import urllib.parse
import socket
import threading
import os
import time
import select
from datetime import datetime


class RobustPS3ProxyHandler(http.server.BaseHTTPRequestHandler):
    """Proxy HTTP robusto que maneja mejor las conexiones"""
    
    # CONFIGURACIÓN
    PUP_FILE = "HFW_4.92.1_PS3UPDAT.PUP"
    OFFER_VERSION = "4.93"
    
    # Timeouts (en segundos)
    CONNECT_TIMEOUT = 10
    RESPONSE_TIMEOUT = 30
    
    # Mapeo completo de regiones a códigos Dest
    REGION_DEST_MAP = {
        # Patrón en URL -> Código Dest
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
        '.ps3.update.playstation.net/update/ps3/list/',           # Ruta de actualización
        'ps3-updatelist.txt',
    ]
    
    def log_message(self, format, *args):
        """Log personalizado con timestamp"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        client_ip = self.client_address[0]
        print(f"[{timestamp}] {client_ip} - {format % args}")
    
    def do_GET(self):
        self._handle_request('GET')
    
    def do_HEAD(self):
        self._handle_request('HEAD')
    
    def do_POST(self):
        self._handle_request('POST')
    
    def do_CONNECT(self):
        """Maneja conexiones HTTPS - importante para navegación segura"""
        print(f"   🔒 CONNECT para HTTPS: {self.path}")
        try:
            # Para HTTPS, simplemente establecer tunnel
            host, port = self.path.split(':', 1)
            port = int(port) if port else 443
            
            # Conectar al servidor destino
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.settimeout(self.CONNECT_TIMEOUT)
            remote_socket.connect((host, port))
            
            # Enviar respuesta 200 al cliente
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            # Establecer tunnel bidireccional
            self._tunnel_sockets(self.connection, remote_socket)
            
        except Exception as e:
            print(f"   ❌ Error CONNECT: {e}")
            self.send_error(502, f"HTTPS Error: {e}")
    
    def _handle_request(self, method):
        """Maneja todas las peticiones HTTP"""
        start_time = time.time()
        
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {method} {self.path}")
        
        # Verificar si es petición PS3 usando detección automática
        if self._is_ps3_update_request():
            print("   🎯 INTERCEPTANDO (PS3 Update)")
            self._handle_ps3_update(method)
        else:
            print("   🔓 REENVIANDO (Tráfico normal)")
            self._forward_http_request(method)
        
        elapsed = time.time() - start_time
        print(f"   ⏱️  Tiempo total: {elapsed:.2f}s")
    
    def _is_ps3_update_request(self):
        """
        Detecta automáticamente peticiones de actualización de PS3
        usando patrones en lugar de una lista fija de dominios
        """
        url = self.path.lower()
        host = self.headers.get('Host', '').lower()
        full_url = f"{host}{url}"
        
        # Detectar por patrones específicos de PS3
        for pattern in self.PS3_UPDATE_PATTERNS:
            if pattern in url or pattern in host:
                print(f"   🔍 Patrón detectado: {pattern}")
                return True
        
        # Detectar por User-Agent de PS3
        user_agent = self.headers.get('User-Agent', '').lower()
        if 'ps3' in user_agent and 'update' in user_agent:
            print(f"   🔍 User-Agent PS3 detectado")
            return True
        
        # Detectar por estructura de URL típica de PS3
        if self._has_ps3_url_structure(url, host):
            return True
            
        return False
    
    def _has_ps3_url_structure(self, url, host):
        """Detecta estructura típica de URLs de actualización PS3"""
        # URLs que contienen patrones de región/país típicos de PS3
        region_patterns = list(self.REGION_DEST_MAP.keys())
        
        # Si la URL tiene estructura /update/ps3/list/[región]/ps3-updatelist.txt
        if '/update/ps3/list/' in url and any(region in url for region in region_patterns):
            print(f"   🔍 Estructura regional PS3 detectada")
            return True
        
        # Si el host contiene 'update' y la URL contiene 'ps3'
        if 'update' in host and 'ps3' in url:
            print(f"   🔍 Host de update con URL PS3 detectado")
            return True
            
        # Si es una petición a un archivo PUP desde cualquier dominio
        if url.endswith('.pup') and ('update' in url or 'ps3' in url):
            print(f"   🔍 Archivo PUP detectado")
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
            print(f"   ❌ Error PS3: {e}")
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
        
        print(f"   ✅ Lista servida - Versión: {self.OFFER_VERSION}, Región: {region_name}, Dest: {dest_code}")
    
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
        print(f"   ⚠️  Región no detectada, usando MX como default")
        return {
            'region': 'Mexico (MX)',
            'dest': '88'
        }
    
    def _serve_pup_file(self, method):
        """Sirve el archivo PUP local"""
        print(f"   💿 Sirviendo: {self.PUP_FILE}")
        
        if not os.path.exists(self.PUP_FILE):
            print(f"   ❌ PUP no encontrado: {self.PUP_FILE}")
            self.send_error(404, f"PUP file not found")
            return
        
        try:
            file_size = os.path.getsize(self.PUP_FILE)
            
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
                print("   ✅ HEAD respondido")
                return
            
            # Para GET - enviar archivo
            self.send_response(200)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            
            # Enviar archivo en chunks
            sent_bytes = 0
            start_time = time.time()
            
            with open(self.PUP_FILE, 'rb') as f:
                while True:
                    chunk = f.read(32768)  # 32KB chunks para mejor rendimiento
                    if not chunk:
                        break
                    
                    try:
                        self.wfile.write(chunk)
                        sent_bytes += len(chunk)
                        
                        # Mostrar progreso cada 10MB
                        if sent_bytes % (10 * 1024 * 1024) == 0:
                            mb_sent = sent_bytes // (1024 * 1024)
                            elapsed = time.time() - start_time
                            speed = (sent_bytes / 1024 / 1024) / elapsed if elapsed > 0 else 0
                            print(f"   📤 Progreso: {mb_sent}MB ({speed:.1f} MB/s)")
                    
                    except (BrokenPipeError, ConnectionResetError):
                        print("   ⚠️  Cliente cerró la conexión")
                        break
            
            total_time = time.time() - start_time
            print(f"   ✅ PUP enviado: {sent_bytes} bytes en {total_time:.1f}s")
            
        except Exception as e:
            print(f"   ❌ Error sirviendo PUP: {e}")
            self.send_error(500, f"Error: {e}")
    
    def _forward_to_sony(self, method):
        """Reenvía peticiones PS3 a Sony"""
        try:
            # Construir URL completa
            if self.path.startswith('http://'):
                url = self.path
            else:
                host = self.headers.get('Host', '')
                if not host:
                    # Si no hay host, usar uno por defecto
                    host = 'dus01.ps3.update.playstation.net'
                url = f"http://{host}{self.path}"
            
            print(f"   🔄 Reenviando a Sony: {url}")
            
            # Headers limpios
            headers = self._get_clean_headers()
            
            # Realizar petición
            req = urllib.request.Request(url, method=method, headers=headers)
            response = urllib.request.urlopen(req, timeout=self.RESPONSE_TIMEOUT)
            
            # Enviar respuesta
            self.send_response(response.getcode())
            for header, value in response.headers.items():
                if header.lower() not in ['transfer-encoding', 'connection']:
                    self.send_header(header, value)
            self.send_header('Connection', 'close')
            self.end_headers()
            
            # Enviar datos
            if method == 'GET':
                self.wfile.write(response.read())
            
            print(f"   ✅ Reenvío exitoso: {response.getcode()}")
            
        except Exception as e:
            print(f"   ❌ Error reenviando a Sony: {e}")
            self.send_error(502, f"Error: {e}")
    
    def _forward_http_request(self, method):
        """Reenvía peticiones HTTP normales de forma robusta"""
        try:
            # Construir URL correcta
            if self.path.startswith('http://'):
                url = self.path
            else:
                host = self.headers.get('Host', '')
                if not host:
                    # Si no hay host, no podemos reenviar
                    self.send_error(400, "No Host header")
                    return
                url = f"http://{host}{self.path}"
            
            print(f"   🔄 Reenviando: {url}")
            
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
            response = urllib.request.urlopen(req, timeout=self.RESPONSE_TIMEOUT)
            
            # Enviar respuesta al cliente
            self.send_response(response.getcode())
            
            # Filtrar headers problemáticos
            for header, value in response.headers.items():
                header_lower = header.lower()
                if header_lower not in ['transfer-encoding', 'content-encoding']:
                    self.send_header(header, value)
            
            self.end_headers()
            
            # Enviar contenido
            if method in ['GET', 'POST']:
                # Leer y enviar en chunks para mejor rendimiento
                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            
            print(f"   ✅ Reenvío exitoso: {response.getcode()}")
            
        except urllib.error.URLError as e:
            print(f"   ❌ Error URL: {e}")
            self.send_error(502, f"Network Error: {e}")
        except socket.timeout:
            print("   ⏰ Timeout en reenvío")
            self.send_error(504, "Gateway Timeout")
        except Exception as e:
            print(f"   ❌ Error reenviando: {e}")
            self.send_error(502, f"Proxy Error: {e}")
    
    def _get_clean_headers(self):
        """Limpia los headers para reenvío"""
        clean_headers = {}
        for key, value in self.headers.items():
            key_lower = key.lower()
            # Eliminar headers de proxy y conexión
            if key_lower not in ['host', 'proxy-connection', 'connection', 'accept-encoding']:
                clean_headers[key] = value
        
        # Headers importantes para compatibilidad
        clean_headers['User-Agent'] = self.headers.get('User-Agent', 'Mozilla/5.0')
        clean_headers['Accept'] = self.headers.get('Accept', '*/*')
        
        return clean_headers
    
    def _tunnel_sockets(self, client_socket, remote_socket):
        """Establece tunnel para conexiones HTTPS"""
        sockets = [client_socket, remote_socket]
        
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 30)
                
                if exceptional:
                    break
                
                for sock in readable:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            break
                        
                        if sock is client_socket:
                            remote_socket.send(data)
                        else:
                            client_socket.send(data)
                    except (socket.timeout, ConnectionResetError, BrokenPipeError):
                        break
                
        finally:
            client_socket.close()
            remote_socket.close()
    
    def _get_local_ip(self):
        """Obtiene la IP local"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Servidor HTTP con soporte para múltiples hilos"""
    daemon_threads = True
    allow_reuse_address = True

def main():
    """Función principal"""
    HOST = '0.0.0.0'
    PORT = 8080
    
    print("🎮 PS3 HFW PROXY - REGIONES AUTOMÁTICAS")
    print("=" * 50)
    print(f"📍 Proxy: http://{get_local_ip()}:{PORT}")
    print(f"📁 PUP: {RobustPS3ProxyHandler.PUP_FILE}")
    print(f"🏷️  Versión: {RobustPS3ProxyHandler.OFFER_VERSION}")
    print()
    print("🌍 REGIONES SOPORTADAS:")
    for dest, name in RobustPS3ProxyHandler.REGION_NAMES.items():
        print(f"   • {name} (Dest={dest})")
    print()
    print("🔧 CONFIGURACIÓN PS3:")
    print(f"   Proxy: {get_local_ip()}:{PORT}")
    print()
    print("⏹️  Ctrl+C para detener")
    print("=" * 50)
    
    # Verificar archivo PUP
    if not os.path.exists(RobustPS3ProxyHandler.PUP_FILE):
        print(f"❌ ERROR: No se encuentra {RobustPS3ProxyHandler.PUP_FILE}")
        print("💡 Coloca el archivo PUP en la misma carpeta")
        return
    
    size = os.path.getsize(RobustPS3ProxyHandler.PUP_FILE)
    print(f"✅ PUP encontrado: {size} bytes ({size//1024//1024} MB)")
    
    try:
        # Crear servidor con soporte para hilos
        server = ThreadedHTTPServer((HOST, PORT), RobustPS3ProxyHandler)
        print(f"\n🚀 Proxy iniciado en puerto {PORT}")
        print("📡 Esperando conexiones...")
        server.serve_forever()
        
    except KeyboardInterrupt:
        print("\n🛑 Proxy detenido por el usuario")
    except Exception as e:
        print(f"❌ Error: {e}")

def get_local_ip():
    """Obtiene la IP local"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1"

if __name__ == '__main__':
    main()
