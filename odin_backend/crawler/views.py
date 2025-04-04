import json
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from .scraper import scrape_page_content, search_web   

# Configure logging
logging.basicConfig(filename="crawler_api.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
        

#threat intelligence

import json
import logging
import platform
import psutil
import os
import time
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys
from webdriver_manager.chrome import ChromeDriverManager
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
import socket
import platform
import psutil

# Configure logging
logging.basicConfig(filename="api.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

@method_decorator(csrf_exempt, name="dispatch")
class SystemInfoView(View):
    def get(self, request):
        try:
            # Get hostname and IP
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            
            # Get all network interface IPs
            all_ips = []
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        all_ips.append(f"{interface}: {addr.address}")
            
            data = {
                "System": platform.system(),
                "Node Name": platform.node(),
                "IP Address": ip_address,
                "All IPs": all_ips,
                "Release": platform.release(),
                "Version": platform.version(),
                "Machine": platform.machine(),
                "Processor": platform.processor(),
                "Physical Cores": psutil.cpu_count(logical=False),
                "Total Cores": psutil.cpu_count(logical=True),
                "Max Frequency": f"{psutil.cpu_freq().max:.2f}Mhz",
                "Memory": f"{psutil.virtual_memory().total / (1024 ** 3):.2f} GB",
            }
            return JsonResponse(data)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    



# Configure logging
logging.basicConfig(filename="file_analysis.log", level=logging.INFO, 
                  format="%(asctime)s - %(levelname)s - %(message)s")

from collections import defaultdict
import os
import time
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View

@method_decorator(csrf_exempt, name='dispatch')
class FileDataView(View):
    """Handle file and directory analysis requests"""
    
    def post(self, request):
        try:
            # Try to parse JSON data first
            try:
                data = json.loads(request.body)
                path = data.get('path', '').strip()
            except json.JSONDecodeError:
                # Fallback to form data if JSON parsing fails
                path = request.POST.get('path', '').strip()
            
            if not path:
                return JsonResponse({'error': 'Path parameter is required'}, status=400)
            
            if not os.path.exists(path):
                return JsonResponse({'error': 'Path does not exist'}, status=400)
            
            if os.path.isfile(path):
                return self.analyze_file(path)
            elif os.path.isdir(path):
                return self.analyze_directory(path)
            else:
                return JsonResponse({'error': 'Invalid path type'}, status=400)
                
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    def analyze_file(self, filepath):
        """Analyze a single file"""
        try:
            filename = os.path.basename(filepath)
            size = os.path.getsize(filepath)
            ext = os.path.splitext(filename)[1].lower()
            
            result = {
                'type': 'file',
                'path': filepath,
                'name': filename,
                'size': size,
                'size_human': self._human_readable_size(size),
                'extension': ext,
                'created': time.ctime(os.path.getctime(filepath)),
                'modified': time.ctime(os.path.getmtime(filepath)),
                'permissions': oct(os.stat(filepath).st_mode)[-3:],
                'content_type': self._get_content_type(filepath, ext)
            }
            
            # Add content analysis for text-based files
            if ext in ['.txt', '.log', '.csv', '.json', '.py', '.js', '.html', '.css']:
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        lines = f.readlines()[:100]  # First 100 lines
                        result['content_sample'] = ''.join(lines)
                except UnicodeDecodeError:
                    result['content_sample'] = 'Binary content - cannot display'
            
            return JsonResponse(result)
            
        except Exception as e:
            return JsonResponse({'error': f'File analysis failed: {str(e)}'}, status=500)
    
    def analyze_directory(self, dirpath):
        """Analyze a directory"""
        try:
            result = {
                'type': 'directory',
                'path': dirpath,
                'file_count': 0,
                'dir_count': 0,
                'total_size': 0,
                'total_size_human': '0 bytes',
                'files_by_type': defaultdict(int),
                'permissions': oct(os.stat(dirpath).st_mode)[-3:],
                'created': time.ctime(os.path.getctime(dirpath)),
                'modified': time.ctime(os.path.getmtime(dirpath)),
                'files': []
            }
            
            for root, dirs, files in os.walk(dirpath):
                result['dir_count'] += len(dirs)
                for file in files:
                    try:
                        filepath = os.path.join(root, file)
                        stat = os.stat(filepath)
                        size = stat.st_size
                        ext = os.path.splitext(file)[1].lower()
                        
                        result['files'].append({
                            'name': file,
                            'path': filepath,
                            'size': size,
                            'size_human': self._human_readable_size(size),
                            'extension': ext,
                            'modified': time.ctime(stat.st_mtime),
                            'permissions': oct(stat.st_mode)[-3:]
                        })
                        
                        result['files_by_type'][ext] += 1
                        result['total_size'] += size
                        result['file_count'] += 1
                    except Exception as e:
                        continue
            
            result['total_size_human'] = self._human_readable_size(result['total_size'])
            return JsonResponse(result)
            
        except Exception as e:
            return JsonResponse({'error': f'Directory analysis failed: {str(e)}'}, status=500)
    
    def _human_readable_size(self, size):
        """Convert size in bytes to human-readable format"""
        for unit in ['bytes', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    def _get_content_type(self, filepath, ext):
        """Simple content type detection"""
        text_types = {
            '.txt': 'text/plain',
            '.csv': 'text/csv',
            '.json': 'application/json',
            '.log': 'text/plain',
            '.py': 'text/x-python',
            '.js': 'application/javascript',
            '.html': 'text/html',
            '.css': 'text/css'
        }
        return text_types.get(ext, 'application/octet-stream')
        
# In views.py
from urllib.parse import unquote, urlparse
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

@method_decorator(csrf_exempt, name="dispatch")
class DuckDuckGoSearchView(View):
    def get(self, request):
        query = request.GET.get('query', '').strip()
        
        if not query:
            return JsonResponse({"error": "Query parameter is required"}, status=400)

        options = Options()
        options.add_argument("--headless")
        options.add_argument("--window-size=1920,1080")
        
        try:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
            driver.get(f"https://duckduckgo.com/?q={query}")

            # Scroll multiple times to load more results
            for _ in range(3):
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(1.5)  # Wait for more results to load

            # Wait for results to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "[data-testid='result']"))
            )

            # Parse all results
            results = []
            for result in driver.find_elements(By.CSS_SELECTOR, "[data-testid='result']"):
                try:
                    title = result.find_element(By.CSS_SELECTOR, "[data-testid='result-title-a']").text
                    link = result.find_element(By.CSS_SELECTOR, "[data-testid='result-extras-url-link']").get_attribute('href')
                    if title and link:
                        results.append({'title': title, 'link': link})
                except:
                    continue

            driver.quit()
            
            return JsonResponse(results[:20], safe=False)  # Return up to 20 results

        except Exception as e:
            if 'driver' in locals():
                driver.quit()
            return JsonResponse({"error": str(e)}, status=500)
        
from cryptography.fernet import Fernet
import base64
import hashlib

@method_decorator(csrf_exempt, name="dispatch")
class AESEncryptionView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            action = data.get("action")  # "encrypt" or "decrypt"
            text = data.get("text")
            key = data.get("key")
            
            if not all([action, text, key]):
                return JsonResponse({"error": "Missing parameters"}, status=400)
            
            # Generate a Fernet key from the user's key
            key_hash = hashlib.sha256(key.encode()).digest()
            fernet_key = base64.urlsafe_b64encode(key_hash)
            cipher = Fernet(fernet_key)
            
            if action == "encrypt":
                encrypted_text = cipher.encrypt(text.encode())
                return JsonResponse({"result": encrypted_text.decode()})
            elif action == "decrypt":
                decrypted_text = cipher.decrypt(text.encode())
                return JsonResponse({"result": decrypted_text.decode()})
            else:
                return JsonResponse({"error": "Invalid action"}, status=400)
                
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
        


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
import scapy.all as scapy
import socket
import psutil
import logging
from concurrent.futures import ThreadPoolExecutor
import time

logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name="dispatch")
class PacketCaptureView(View):
    def get_available_interfaces(self):
        """Get available network interfaces using psutil"""
        try:
            interfaces = psutil.net_if_addrs().keys()
            return list(interfaces)
        except Exception as e:
            logger.error(f"Error getting interfaces: {str(e)}")
            return ["eth0", "wlan0", "lo"]  # Default fallback

    def get(self, request):
        """Handle GET request for interface listing"""
        try:
            interfaces = self.get_available_interfaces()
            return JsonResponse({
                "status": "success",
                "available_interfaces": interfaces
            })
        except Exception as e:
            return JsonResponse({
                "status": "error",
                "error": str(e),
                "message": "Failed to get network interfaces"
            }, status=500)

    def _capture_packets(self, interface, count, timeout=10):
        """Capture packets using scapy"""
        packets = []
        start_time = time.time()
        
        def packet_handler(packet):
            nonlocal packets
            if len(packets) >= count:
                return False  # Stop sniffing
            
            try:
                packet_info = self._parse_packet(packet)
                packets.append(packet_info)
            except Exception as e:
                logger.warning(f"Error parsing packet: {str(e)}")
            
            # Check timeout
            if time.time() - start_time > timeout:
                return False
            
            return True

        try:
            scapy.sniff(
                iface=interface,
                prn=packet_handler,
                store=False,
                timeout=timeout
            )
            return packets
        except Exception as e:
            logger.error(f"Scapy capture error: {str(e)}")
            raise Exception(f"Packet capture failed: {str(e)}")

    def _parse_packet(self, packet):
        """Parse scapy packet into readable format"""
        try:
            # Get basic packet info
            packet_time = time.strftime('%H:%M:%S', time.localtime(packet.time))
            protocol = packet.name.upper() if hasattr(packet, 'name') else 'UNKNOWN'
            
            # Get source and destination
            src = dst = 'N/A'
            if scapy.IP in packet:
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
            elif scapy.IPv6 in packet:
                src = packet[scapy.IPv6].src
                dst = packet[scapy.IPv6].dst
            elif scapy.Ether in packet:
                src = packet[scapy.Ether].src
                dst = packet[scapy.Ether].dst
            
            # Get additional info based on protocol
            info = ''
            if scapy.TCP in packet:
                info = f"TCP {packet[scapy.TCP].sport} → {packet[scapy.TCP].dport}"
            elif scapy.UDP in packet:
                info = f"UDP {packet[scapy.UDP].sport} → {packet[scapy.UDP].dport}"
            elif scapy.DNS in packet:
                info = "DNS Query" if packet[scapy.DNS].qr == 0 else "DNS Response"
            elif scapy.ICMP in packet:
                info = f"ICMP Type {packet[scapy.ICMP].type}"
            
            return {
                'time': packet_time,
                'source': src,
                'destination': dst,
                'protocol': protocol,
                'length': len(packet),
                'info': info
            }
        except Exception as e:
            logger.warning(f"Packet parsing error: {str(e)}")
            return {
                'time': 'N/A',
                'source': 'N/A',
                'destination': 'N/A',
                'protocol': 'UNKNOWN',
                'length': 0,
                'info': 'Failed to parse packet'
            }

    def post(self, request):
        """Handle POST request for packet capture"""
        try:
            interface = request.POST.get("interface", "").strip()
            if not interface:
                return JsonResponse({
                    "status": "error",
                    "error": "Interface parameter is required"
                }, status=400)
                
            try:
                count = min(int(request.POST.get("count", "10")), 100)
            except ValueError:
                return JsonResponse({
                    "status": "error",
                    "error": "Invalid packet count (must be integer)"
                }, status=400)
            
            # Verify interface exists
            available_interfaces = self.get_available_interfaces()
            if interface not in available_interfaces:
                return JsonResponse({
                    "status": "error",
                    "error": f"Interface {interface} not available",
                    "available_interfaces": available_interfaces
                }, status=400)
            
            try:
                # Run capture in a thread
                with ThreadPoolExecutor(max_workers=1) as executor:
                    packets = executor.submit(
                        self._capture_packets,
                        interface, count
                    ).result(timeout=20)  # Timeout for the thread
                
                return JsonResponse({
                    "status": "success",
                    "interface": interface,
                    "packets": packets,
                    "count": len(packets)
                })
                
            except Exception as capture_error:
                logger.error(f"Capture failed: {str(capture_error)}")
                return JsonResponse({
                    "status": "error",
                    "error": str(capture_error),
                    "solution": "Try running with sudo or check interface name",
                    "available_interfaces": available_interfaces
                }, status=500)
                
        except Exception as e:
            logger.error(f"Server error: {str(e)}")
            return JsonResponse({
                "status": "error",
                "error": "Internal server error",
                "details": str(e)
            }, status=500)
        
        

import requests
from bs4 import BeautifulSoup
import re
import requests
import json
import re
import socket
from urllib.parse import urljoin
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
import logging

logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name="dispatch")
class VulnerabilityScanView(View):
    def __init__(self):
        self.timeout = 15
        self.headers = {
            "User-Agent": "SecurityScanner/1.0",
            "Accept": "text/html,application/xhtml+xml"
        }
        self.safe_mode = True  # Prevents aggressive tests

    def validate_target(self, target):
        """Validate and normalize the target"""
        target = target.strip()
        if not re.match(r'^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?$', target, re.I) and \
           not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$', target):
            raise ValueError("Invalid target format. Use domain.com or 192.168.1.1")
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"  # Default to HTTP
            
        return target.rstrip('/')

    def safe_request(self, url, method='GET', **kwargs):
        """Make safe HTTP requests with protections"""
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('headers', self.headers)
            kwargs.setdefault('verify', False)  # For testing only
            
            if self.safe_mode:
                if method == 'POST':
                    kwargs['data'] = kwargs.get('data', '')[:100]  # Limit POST data
                if 'params' in kwargs:
                    kwargs['params'] = {k: v[:50] for k, v in kwargs['params'].items()}
            
            return requests.request(method, url, **kwargs)
        except requests.RequestException as e:
            logger.warning(f"Request to {url} failed: {str(e)}")
            return None

    def check_common_vulns(self, base_url):
        """Check for common vulnerabilities"""
        vulns = []
        
        # 1. Directory/File Discovery
        common_paths = [
            'admin/', 'wp-admin/', 'phpmyadmin/', 
            '.git/', '.env', 'config.php.bak'
        ]
        
        for path in common_paths:
            url = urljoin(base_url, path)
            resp = self.safe_request(url)
            if resp and resp.status_code == 200:
                vulns.append(f"Exposed sensitive path: {path}")

        # 2. XSS Test
        test_url = urljoin(base_url, f"search?q=<script>alert(1)</script>")
        resp = self.safe_request(test_url)
        if resp and "<script>alert(1)</script>" in resp.text:
            vulns.append("Reflected XSS vulnerability detected")

        # 3. SQL Injection
        test_url = urljoin(base_url, "products?id=1'")
        resp = self.safe_request(test_url)
        if resp and ("SQL syntax" in resp.text or "MySQL" in resp.text):
            vulns.append("SQL injection vulnerability detected")

        # 4. CORS Misconfiguration
        resp = self.safe_request(base_url)
        if resp and 'Access-Control-Allow-Origin' in resp.headers:
            if resp.headers['Access-Control-Allow-Origin'] == '*':
                vulns.append("Insecure CORS policy: Allow-Origin: *")

        # 5. Security Headers Check
        security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options'
        ]
        missing_headers = [h for h in security_headers if h not in resp.headers]
        if missing_headers:
            vulns.append(f"Missing security headers: {', '.join(missing_headers)}")

        return vulns

    def port_scan(self, host, ports=[80, 443, 8080, 22, 21]):
        """Basic port scan"""
        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((host, port))
                    if result == 0:
                        open_ports.append(port)
            except:
                continue
        return open_ports

    def post(self, request):
        try:
            data = json.loads(request.body)
            raw_target = data.get('target', '').strip()
            
            if not raw_target:
                return JsonResponse({"error": "Target is required"}, status=400)
            
            try:
                target = self.validate_target(raw_target)
            except ValueError as e:
                return JsonResponse({"error": str(e)}, status=400)
            
            # Extract host for port scanning
            host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
            
            results = {
                "target": target,
                "vulnerabilities": [],
                "open_ports": [],
                "security_grade": "A"
            }
            
            # Port Scanning
            results["open_ports"] = self.port_scan(host)
            
            # Web Vulnerability Checks
            if 80 in results["open_ports"] or 443 in results["open_ports"]:
                results["vulnerabilities"] = self.check_common_vulns(target)
            
            # Grade Calculation
            if results["vulnerabilities"]:
                results["security_grade"] = "D" if len(results["vulnerabilities"]) > 3 else "C"
            elif not results["open_ports"]:
                results["security_grade"] = "F"
            
            return JsonResponse({
                "status": "success",
                "results": results,
                "scan_config": {
                    "safe_mode": self.safe_mode,
                    "tests_performed": 15
                }
            })
            
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON input"}, status=400)
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            return JsonResponse({"error": "Scan failed. Please try again."}, status=500)


@method_decorator(csrf_exempt, name="dispatch")
class DarkWebSearchView(View):
    def get(self, request):
        query = request.GET.get('query', '').strip()
        if not query:
            return JsonResponse({"error": "Query parameter is required"}, status=400)

        options = Options()
        options.add_argument('--proxy-server=socks5://127.0.0.1:9050')  # Using Tor proxy
        options.add_argument("--headless")
        service = Service(ChromeDriverManager().install())
        
        try:
            driver = webdriver.Chrome(service=service, options=options)
            driver.get("https://ahmia.fi")

            search_box = driver.find_element("name", "q")
            search_box.send_keys(query)
            search_box.send_keys(Keys.RETURN)
            time.sleep(10)

            soup = BeautifulSoup(driver.page_source, 'html.parser')
            results = soup.find_all('a', class_='result__a')

            search_results = [{"title": result.get_text(), "link": result.get('href')} for result in results]
            driver.quit()
            return JsonResponse(search_results, safe=False)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

@method_decorator(csrf_exempt, name="dispatch")
class FileDataExtractionView(View):
    def get(self, request):
        directory = request.GET.get('directory', '').strip()
        if not directory or not os.path.exists(directory):
            return JsonResponse({"error": "Directory not found or not provided"}, status=400)

        categorized_files = {
            'csv': [], 'pdf': [], 'txt': [], 'images': [], 'videos': [], 'other': []
        }

        image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.bmp')
        video_extensions = ('.mp4', '.mov', '.avi', '.mkv')

        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    extension = os.path.splitext(file)[1].lower()

                    if extension == '.csv':
                        categorized_files['csv'].append(file_path)
                    elif extension == '.pdf':
                        categorized_files['pdf'].append(file_path)
                    elif extension == '.txt':
                        categorized_files['txt'].append(file_path)
                    elif extension in image_extensions:
                        categorized_files['images'].append(file_path)
                    elif extension in video_extensions:
                        categorized_files['videos'].append(file_path)
                    else:
                        categorized_files['other'].append(file_path)

            return JsonResponse(categorized_files)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
        

import json
import logging
import nmap
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View

logger = logging.getLogger(__name__)


import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View

logger = logging.getLogger(__name__)

# In your views.py
import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View

logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name="dispatch")
class TextOptionView(View):
    # Expanded list of common ports and services
    COMMON_PORTS_SERVICES = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
        25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
        80: "http", 110: "pop3", 123: "ntp", 143: "imap",
        161: "snmp", 162: "snmptrap", 179: "bgp", 389: "ldap",
        443: "https", 445: "smb", 465: "smtps", 514: "syslog",
        587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s",
        1080: "socks", 1194: "openvpn", 1433: "ms-sql", 1521: "oracle",
        1723: "pptp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
        2086: "whm", 2087: "whm-ssl", 2095: "webmail", 2096: "webmail-ssl",
        2181: "zookeeper", 2222: "directadmin", 2375: "docker", 2376: "docker-ssl",
        3000: "nodejs", 3306: "mysql", 3389: "rdp", 3690: "svn",
        4333: "mssql", 4444: "metasploit", 4500: "ipsec-nat-t", 4567: "sinatra",
        4848: "glassfish", 4900: "matahari", 5000: "upnp", 5432: "postgresql",
        5601: "kibana", 5900: "vnc", 5984: "couchdb", 6379: "redis",
        7001: "weblogic", 8000: "http-alt", 8008: "http-alt", 8080: "http-alt",
        8081: "http-alt", 8088: "radan-http", 8090: "http-alt", 8091: "couchbase",
        8140: "puppet", 8333: "bitcoin", 8443: "https-alt", 8888: "sun-answerbook",
        9000: "jenkins", 9042: "cassandra", 9090: "websm", 9091: "xmltec-xmlmail",
        9100: "jetdirect", 9200: "elasticsearch", 9300: "elasticsearch", 9418: "git",
        9999: "abyss", 10000: "webmin", 11211: "memcache", 27017: "mongodb",
        28017: "mongodb-http", 50000: "db2", 50030: "hadoop", 50060: "hadoop",
        50070: "hadoop", 50075: "hadoop"
    }

    def check_port(self, host, port, timeout=1.5):
        """Check if a port is open using Python sockets"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return port if result == 0 else None
        except Exception as e:
            logger.debug(f"Port {port} check error: {str(e)}")
            return None

    def perform_scan(self, target):
        """Perform the actual port scan"""
        open_ports = []
        
        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {
                executor.submit(self.check_port, target, port): port 
                for port in self.COMMON_PORTS_SERVICES.keys()
            }
            
            for future in futures:
                port = futures[future]
                try:
                    if future.result() is not None:
                        open_ports.append(port)
                except Exception as e:
                    logger.debug(f"Port {port} scan failed: {str(e)}")
        
        return sorted(open_ports)

    def post(self, request):
        try:
            data = json.loads(request.body.decode("utf-8"))
            option = data.get("option")
            target = data.get("target", "").strip()
            
            if option == "Nmap scan":
                if not target:
                    return JsonResponse({"error": "Target IP or domain is required"}, status=400)
                
                try:
                    open_ports = self.perform_scan(target)
                    
                    # Format results in Nmap-style output
                    scan_results = {
                        "target": target,
                        "open_ports": [
                            {
                                "port": port,
                                "service": self.COMMON_PORTS_SERVICES.get(port, "unknown"),
                                "state": "open"
                            } 
                            for port in open_ports
                        ],
                        "scan_method": "python_socket"
                    }
                    
                    return JsonResponse({
                        "status": "success",
                        "scan_results": scan_results
                    })
                    
                except Exception as e:
                    logger.error(f"Scan failed for {target}: {str(e)}")
                    return JsonResponse({
                        "error": f"Port scan failed: {str(e)}",
                        "suggestion": "Try again or check your network connection"
                    }, status=500)
            
            return JsonResponse({"error": "Unsupported option"}, status=400)
            
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data"}, status=400)
        except Exception as e:
            logger.error(f"Server error: {str(e)}")
            return JsonResponse({"error": "Internal server error"}, status=500)

        
# Audio      
import os
from django.http import JsonResponse
from django.views import View
from django.conf import settings
import speech_recognition as sr
from googletrans import Translator
import tempfile
import logging
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name='dispatch')
class AudioProcessingView(View):
    def post(self, request):
        # Check if audio file was uploaded
        if 'audio_file' not in request.FILES:
            return JsonResponse({'error': 'No audio file provided'}, status=400)
        
        # Get target language from form data
        target_language = request.POST.get('target_language', 'hi')  # Default to Hindi
        
        audio_file = request.FILES['audio_file']
        
        try:
            # Save the uploaded file temporarily
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as tmp_file:
                for chunk in audio_file.chunks():
                    tmp_file.write(chunk)
                tmp_file_path = tmp_file.name
            
            # Initialize speech recognizer
            recognizer = sr.Recognizer()
            
            # Recognize speech from audio file
            with sr.AudioFile(tmp_file_path) as source:
                audio_data = recognizer.record(source)
                transcription = recognizer.recognize_google(audio_data)
            
            # Translate the transcription
            translator = Translator()
            translation = translator.translate(transcription, dest=target_language).text
            
            # Clean up temporary file
            try:
                os.unlink(tmp_file_path)
            except Exception as e:
                logger.warning(f"Could not delete temp file: {e}")
            
            return JsonResponse({
                'transcription': transcription,
                'translation': translation
            })
            
        except sr.UnknownValueError:
            return JsonResponse({'error': 'Could not understand audio'}, status=400)
        except sr.RequestError as e:
            return JsonResponse({'error': f'Speech recognition service error: {e}'}, status=500)
        except Exception as e:
            logger.error(f"Error processing audio: {e}")
            return JsonResponse({'error': 'Error processing audio'}, status=500)
        
@method_decorator(csrf_exempt, name='dispatch')
class TextTranslationView(View):
    def post(self, request):
        try:
            import json
            data = json.loads(request.body)
            text = data.get('text')
            target_language = data.get('target_language', 'hi')  # Default to Hindi
            
            if not text:
                return JsonResponse({'error': 'No text provided'}, status=400)
            
            # Translate the text
            translator = Translator()
            translation = translator.translate(text, dest=target_language).text
            
            return JsonResponse({
                'translation': translation
            })
            
        except Exception as e:
            logger.error(f"Error translating text: {e}")
            return JsonResponse({'error': 'Error translating text'}, status=500)


#darkweb
import re
import logging
import socket
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from urllib.parse import urljoin, urlparse
import time
from collections import Counter

logger = logging.getLogger(__name__)

# Detection patterns
SENSITIVE_PATTERNS = {
    "Personal Data": {
        "keywords": ["full name", "phone", "address", "ssn", "social security", "passport", "dob"],
        "regex": r'\b\d{3}-\d{2}-\d{4}\b'
    },
    "Financial": {
        "keywords": ["credit card", "bank account", "routing", "swift", "iban", "cvv"],
        "regex": r'\b(?:\d[ -]*?){13,16}\b'
    },
    "Credentials": {
        "keywords": ["username", "password", "login", "credentials", "2fa"],
        "regex": r'(?i)(pass(word|code)|secret|key|token)[:=]\s*[\'"\w+]'
    },
    "Cryptocurrency": {
        "keywords": ["bitcoin", "monero", "wallet"],
        "regex": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    }
}

INDICATOR_PATTERNS = {
    "bitcoin_addresses": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    "email_addresses": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "phone_numbers": r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
}

# Updated resources including DuckDuckGo
DARKWEB_RESOURCES = [
    # Search Engines
    ("http://darkfailllnkf4vf.onion", "DarkFail", "search", "Search Engine"),
    ("http://grams7enufi7jmdl.onion", "Grams", "search", "Search Engine"),
    ("https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", "DuckDuckGo", "search", "Search Engine"),
    
    # Marketplaces
    ("http://torrezmarket.onion", "Torrez Market", "market", "Marketplace"),
    ("http://monopolyymv3mioq.onion", "Monopoly Market", "market", "Marketplace"),
    
    # Forums
    ("http://dreadditevelidot.onion", "Dread Forum", "forum", "Forum")
]

def check_tor_connection():
    """Check Tor connection status"""
    ports_to_check = [
        (9150, "Tor Browser"),
        (9050, "Tor Service"),
        (9151, "Tor Browser (alternative)")
    ]
    
    for port, source in ports_to_check:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5):
                test_proxy = {
                    "http": f"socks5h://127.0.0.1:{port}",
                    "https": f"socks5h://127.0.0.1:{port}"
                }
                try:
                    response = requests.get(
                        "http://check.torproject.org",
                        proxies=test_proxy,
                        timeout=10
                    )
                    if "Congratulations" in response.text:
                        return port, source
                except:
                    continue
        except (socket.timeout, ConnectionRefusedError):
            continue
    
    return None, None

def create_tor_session():
    """Create Tor session with retry logic"""
    session = requests.Session()
    
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[408, 429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    port, source = check_tor_connection()
    if not port:
        raise ConnectionError(
            "Failed to establish Tor connection\n\n"
            "Troubleshooting Guide:\n"
            "1. For Windows:\n"
            "   - Keep Tor Browser running\n"
            "   - Verify no firewall blocks ports 9150/9050\n"
            "2. For Linux:\n"
            "   - Install: sudo apt install tor\n"
            "   - Start: sudo service tor start\n"
            "3. General:\n"
            "   - Check system proxy settings\n"
            "   - Try restarting Tor\n"
            "   - Verify Tor isn't blocked by your ISP"
        )
    
    session.proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}"
    }
    
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive'
    })
    
    return session

def validate_onion_url(url):
    """Validate .onion URLs"""
    try:
        parsed = urlparse(url)
        return (
            parsed.scheme in ('http', 'https') and
            parsed.netloc.endswith('.onion') and
            len(parsed.netloc) >= 16
        )
    except:
        return False

def extract_page_metadata(soup, url):
    """Extract page metadata"""
    metadata = {
        "title": soup.title.string.strip() if soup.title else "No title found",
        "url": url,
        "headers": [],
        "links": [],
        "forms": [],
        "security_indicators": []
    }
    
    for level in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
        for heading in soup.find_all(level):
            metadata["headers"].append({
                "level": level.upper(),
                "text": heading.get_text().strip()
            })
    
    seen_links = set()
    for link in soup.find_all('a', href=True):
        href = link['href']
        if href.startswith('http') and href not in seen_links:
            seen_links.add(href)
            metadata["links"].append({
                "text": link.get_text().strip()[:100],
                "url": href,
                "is_external": not href.endswith('.onion')
            })
    
    for form in soup.find_all('form'):
        form_data = {
            "action": form.get('action', ''),
            "method": form.get('method', 'get').upper(),
            "inputs": []
        }
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            form_data["inputs"].append({
                "type": input_tag.get('type', input_tag.name),
                "name": input_tag.get('name', '')
            })
        metadata["forms"].append(form_data)
    
    if soup.find('form') and not soup.find('input', {'type': 'hidden', 'name': 'csrfmiddlewaretoken'}):
        metadata["security_indicators"].append("Missing CSRF protection in forms")
    
    if any(form.get('method', '').lower() == 'get' for form in soup.find_all('form')):
        metadata["security_indicators"].append("Form using GET method (credentials may be exposed in URL)")
    
    return metadata

def detect_sensitive_content(content):
    """Detect sensitive information"""
    findings = []
    content_lower = content.lower()
    
    for category, patterns in SENSITIVE_PATTERNS.items():
        found_keywords = [
            kw for kw in patterns["keywords"] 
            if kw in content_lower
        ]
        
        regex_matches = []
        if "regex" in patterns:
            matches = re.findall(patterns["regex"], content)
            if matches:
                regex_matches = list(set(matches))[:5]
        
        if found_keywords or regex_matches:
            findings.append({
                "category": category,
                "keywords": found_keywords,
                "matches": regex_matches
            })
    
    return findings

def detect_indicators(content):
    """Detect common indicators"""
    indicators = {
        "bitcoin_addresses": [],
        "email_addresses": [],
        "phone_numbers": []
    }
    
    for indicator_type, pattern in INDICATOR_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            indicators[indicator_type] = list(set(matches))[:10]
    
    return indicators

def calculate_stats(content, soup):
    """Calculate page statistics"""
    words = re.findall(r'\w+', content)
    word_count = len(words)
    
    word_freq = Counter(word.lower() for word in words if len(word) > 3)
    common_words = dict(word_freq.most_common(10))
    
    return {
        "word_count": word_count,
        "link_count": len(soup.find_all('a')),
        "image_count": len(soup.find_all('img')),
        "common_words": common_words
    }

def search_darkweb(session, keyword):
    """Enhanced Dark Web search with better result extraction"""
    results = []
    
    try:
        ddg_url = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        search_url = f"{ddg_url}/?q={keyword}&kp=-1&ia=web"
        
        time.sleep(2)  # Be more polite with delay
        response = session.get(search_url, timeout=60)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Method 1: Improved search result extraction
        for result in soup.select('.result'):
            try:
                # Get the main link
                main_link = result.select_one('.result__title a')
                if not main_link:
                    continue
                    
                href = main_link.get('href', '')
                title = main_link.get_text().strip()
                
                # Skip non-onion and empty results
                if not href or not href.endswith('.onion') or not title:
                    continue
                
                # Get description
                snippet = result.select_one('.result__snippet')
                description = snippet.get_text().strip() if snippet else "No description available"
                
                # Get additional links from the result
                extra_links = []
                for link in result.select('a[href*=".onion"]'):
                    extra_href = link.get('href')
                    if extra_href != href:
                        extra_links.append(extra_href)
                
                # Add main result
                results.append({
                    "title": title[:120],
                    "url": href,
                    "description": description[:200],
                    "category": "Dark Web",
                    "source": "DuckDuckGo",
                    "type": "search"
                })
                
                # Add any extra onion links found in this result
                for extra_href in extra_links[:2]:  # Limit to 2 extra links per result
                    results.append({
                        "title": f"Related link from {title[:50]}",
                        "url": extra_href,
                        "description": "Additional onion service mentioned in result",
                        "category": "Dark Web",
                        "source": "DuckDuckGo",
                        "type": "related"
                    })
                    
            except Exception as e:
                logger.warning(f"Error processing result: {str(e)}")
                continue
        
        # Method 2: Direct page scanning if no results
        if not results:
            seen = set()
            for link in soup.find_all('a', href=re.compile(r'\.onion($|/)')):
                href = link.get('href')
                if href and href not in seen:
                    seen.add(href)
                    title = link.get_text().strip() or "Onion Service"
                    results.append({
                        "title": title[:120],
                        "url": href,
                        "description": "Found in page content",
                        "category": "Dark Web",
                        "source": "DuckDuckGo",
                        "type": "scraped"
                    })
        
        # Method 3: Known sites fallback for common queries
        known_resources = {
            "hiddenwiki": [
                ("The Hidden Wiki (Official)", "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/"),
                ("Tor Links Directory", "http://torlinksd6pdnihy.onion/"),
                ("Dark.Fail Verified Links", "http://darkfailllnkf4vf.onion/"),
                ("Onion Links Collection", "http://visitorfi5kl7q7i.onion/")
            ],
            "market": [
                ("Torrez Market", "http://torrezmarket.onion"),
                ("Monopoly Market", "http://monopolyymv3mioq.onion"),
                ("DarkMarket", "http://darkmarketcypher.com.onion")
            ],
            "forum": [
                ("Dread Forum", "http://dreadditevelidot.onion"),
                ("The Hub Forum", "http://thehub7gqe43miyc.onion")
            ]
        }
        
        # Add known resources if they match the search term
        keyword_lower = keyword.lower()
        for kw, resources in known_resources.items():
            if kw in keyword_lower and not any(r['source'] == 'System' for r in results):
                results.extend({
                    "title": name,
                    "url": url,
                    "description": "Verified dark web resource",
                    "category": "Dark Web",
                    "source": "System",
                    "type": "directory"
                } for name, url in resources)
                break
        
        # Final formatting and deduplication
        unique_results = []
        seen_urls = set()
        for result in results:
            if result['url'] not in seen_urls:
                seen_urls.add(result['url'])
                unique_results.append(result)
        
        if not unique_results:
            unique_results.append({
                "title": f"No results found for '{keyword}'",
                "url": ddg_url,
                "description": "Try different keywords like 'wiki', 'market', or 'forum'",
                "category": "Search",
                "source": "DuckDuckGo",
                "type": "search"
            })
        
        return unique_results[:15]
            
    except Exception as e:
        logger.error(f"Search failed: {str(e)}")
        # Return known resources even on failure for common terms
        if "hiddenwiki" in keyword.lower():
            return [{
                "title": "The Hidden Wiki (Official)",
                "url": "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/",
                "description": "Official Hidden Wiki mirror",
                "category": "Dark Web",
                "source": "System",
                "type": "directory"
            }]
        return [{
            "title": "Search failed",
            "url": "",
            "description": f"Error: {str(e)}. Try again later.",
            "category": "Error",
            "source": "System",
            "type": "error"
        }]

@method_decorator(csrf_exempt, name='dispatch')
class DarkWebOperationView(View):
    def post(self, request):
        try:
            action = request.POST.get("action")
            if action not in ["extract", "search"]:
                return JsonResponse(
                    {"success": False, "error": "Invalid action parameter"},
                    status=400
                )
            
            max_retries = 2
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    session = create_tor_session()
                    break
                except ConnectionError as e:
                    last_exception = e
                    if attempt == max_retries:
                        return JsonResponse(
                            {"success": False, "error": str(e)},
                            status=503
                        )
                    time.sleep(1)
                    continue
            
            if action == "extract":
                url = request.POST.get("onion_url", "").strip()
                if not validate_onion_url(url):
                    return JsonResponse(
                        {"success": False, "error": "Invalid .onion URL format"},
                        status=400
                    )
                
                try:
                    start_time = time.time()
                    response = session.get(url, timeout=45)
                    response.raise_for_status()
                    load_time = time.time() - start_time
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    metadata = extract_page_metadata(soup, url)
                    sensitive_info = detect_sensitive_content(response.text)
                    indicators = detect_indicators(response.text)
                    stats = calculate_stats(response.text, soup)
                    
                    return JsonResponse({
                        "success": True,
                        "metadata": {
                            **metadata,
                            "stats": stats
                        },
                        "sensitive_info": sensitive_info,
                        "indicators": indicators,
                        "stats": {
                            "page_size": len(response.content),
                            "load_time": load_time,
                            "status_code": response.status_code
                        }
                    })
                    
                except requests.Timeout:
                    return JsonResponse(
                        {"success": False, "error": "Request timed out. The site may be slow or unavailable."},
                        status=504
                    )
                except requests.RequestException as e:
                    return JsonResponse(
                        {"success": False, "error": f"Failed to access the onion site: {str(e)}"},
                        status=502
                    )
            
            elif action == "search":
                keyword = request.POST.get("keyword", "").strip()
                if not keyword or len(keyword) < 2:
                    return JsonResponse(
                        {"success": False, "error": "Keyword must be at least 2 characters"},
                        status=400
                    )
                
                results = search_darkweb(session, keyword)
                
                return JsonResponse({
                    "success": True,
                    "darkwebResults": results
                })
        
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}", exc_info=True)
            return JsonResponse(
                {"success": False, "error": "Internal server error"},
                status=500
            )

@method_decorator(csrf_exempt, name='dispatch')
class TorStatusView(View):
    def get(self, request):
        try:
            port, source = check_tor_connection()
            if port:
                return JsonResponse({
                    "status": f"Running via {source}",
                    "port": port,
                    "instructions": "Tor connection is active and working"
                })
            
            return JsonResponse({
                "status": "Not connected",
                "instructions": (
                    "Tor is not running or not properly configured.\n"
                    "Please start Tor Browser or install Tor service."
                )
            }, status=503)
            
        except Exception as e:
            return JsonResponse({
                "status": "Error checking status",
                "error": str(e)
            }, status=500)

#image

from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import os
import requests
from bs4 import BeautifulSoup
from stem import Signal
from stem.control import Controller
import random
import time
from urllib.parse import urlparse
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import uuid
import json

class TorManager:
    @staticmethod
    def setup_tor():
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                # Get new identity
                time.sleep(5)  # Wait for new circuit
        except Exception as e:
            print(f"Tor setup failed: {e}")

    @staticmethod
    def get_tor_session():
        session = requests.session()
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        return session

import requests
from django.http import JsonResponse
from django.views import View
from bs4 import BeautifulSoup
import random
import time
from urllib.parse import quote
import os
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import uuid

class ImageSearchView(View):
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
    ]

    def get(self, request):
        keyword = request.GET.get('keyword', '').strip()
        if not keyword:
            return JsonResponse({'error': 'Keyword is required'}, status=400)

        try:
            # Try direct search first
            return self.direct_image_search(keyword)
        except Exception as e:
            print(f"Direct search failed: {e}")
            try:
                # Try Tor search if direct fails
                return self.tor_image_search(keyword)
            except Exception as tor_error:
                print(f"Tor search failed: {tor_error}")
                return JsonResponse({
                    'error': 'All search methods failed',
                    'images': self.get_sample_images()  # Fallback to sample images
                })

    def tor_image_search(self, keyword):
        TorManager.setup_tor()
        session = TorManager.get_tor_session()
        
        headers = {
            'User-Agent': random.choice(self.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        }

        try:
            # Try DuckDuckGo via Tor
            search_url = f'https://duckduckgo.com/?q={quote(keyword)}&iax=images&ia=images'
            response = session.get(search_url, headers=headers, timeout=30)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            image_results = []
            for img in soup.select('.tile--img__img')[:15]:
                src = img.get('src') or img.get('data-src')
                if src and src.startswith('http'):
                    image_results.append(src)

            return JsonResponse({
                'images': list(set(image_results))[:12],
                'source': 'tor'
            })
        except Exception as e:
            raise Exception(f"Tor search failed: {str(e)}")

    def direct_image_search(self, keyword):
        headers = {
            'User-Agent': random.choice(self.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        }

        image_results = []
        
        # Try Bing
        try:
            search_url = f'https://www.bing.com/images/search?q={quote(keyword)}&first=1'
            response = requests.get(search_url, headers=headers, timeout=15)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for img in soup.select('.mimg')[:15]:
                src = img.get('src') or img.get('data-src')
                if src and (src.startswith('http') or src.startswith('//')):
                    image_results.append(src if src.startswith('http') else f'https:{src}')
        except Exception as e:
            print(f"Bing search failed: {e}")

        # Try DuckDuckGo if Bing failed
        if not image_results:
            try:
                search_url = f'https://duckduckgo.com/?q={quote(keyword)}&iax=images&ia=images'
                response = requests.get(search_url, headers=headers, timeout=15)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for img in soup.select('.tile--img__img')[:15]:
                    src = img.get('src') or img.get('data-src')
                    if src and src.startswith('http'):
                        image_results.append(src)
            except Exception as e:
                print(f"DuckDuckGo search failed: {e}")

        if not image_results:
            raise Exception("All direct search methods failed")

        # Return unique images
        return JsonResponse({
            'images': list(set(image_results))[:12],
            'source': 'direct'
        })

    def get_sample_images(self):
        """Fallback sample images when search fails"""
        return [
            "https://via.placeholder.com/300/09f/fff.png",
            "https://via.placeholder.com/300/f90/fff.png",
            "https://via.placeholder.com/300/0f9/fff.png"
        ]

class ImageDownloadView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            urls = data.get('urls', [])[:10]  # Limit to 10 downloads
            
            if not urls:
                return JsonResponse({'error': 'No image URLs provided'}, status=400)
            
            download_folder = 'media/downloaded_images'
            os.makedirs(download_folder, exist_ok=True)
            downloaded_files = []
            failed_downloads = []
            
            for url in urls:
                try:
                    # Verify URL is valid
                    parsed = urlparse(url)
                    if not all([parsed.scheme, parsed.netloc]):
                        raise ValueError("Invalid URL format")
                    
                    # Set timeout and headers
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                    
                    # Start download
                    response = requests.get(url, headers=headers, stream=True, timeout=15)
                    response.raise_for_status()
                    
                    # Check content type is image
                    content_type = response.headers.get('content-type', '')
                    if 'image' not in content_type:
                        raise ValueError(f"URL doesn't point to an image (Content-Type: {content_type})")
                    
                    # Generate unique filename with proper extension
                    ext = self.guess_extension(content_type) or os.path.splitext(parsed.path)[1] or '.jpg'
                    filename = f"{uuid.uuid4().hex}{ext}"
                    filepath = os.path.join(download_folder, filename)
                    
                    # Download with progress
                    total_size = int(response.headers.get('content-length', 0))
                    downloaded = 0
                    
                    with open(filepath, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:  # filter out keep-alive new chunks
                                f.write(chunk)
                                downloaded += len(chunk)
                    
                    # Verify file was downloaded
                    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
                        raise ValueError("Downloaded file is empty or missing")
                    
                    downloaded_files.append({
                        'url': url,
                        'path': filepath,
                        'size': os.path.getsize(filepath),
                        'content_type': content_type
                    })
                    
                except Exception as e:
                    print(f"Failed to download {url}: {str(e)}")
                    failed_downloads.append({
                        'url': url,
                        'error': str(e)
                    })
                    continue
            
            return JsonResponse({
                'success': True,
                'downloaded': len(downloaded_files),
                'failed': len(failed_downloads),
                'files': downloaded_files,
                'errors': failed_downloads
            })
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    def guess_extension(self, content_type):
        """Guess file extension from content type"""
        mapping = {
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'image/webp': '.webp',
            'image/svg+xml': '.svg',
        }
        return mapping.get(content_type.lower())
    


logger = logging.getLogger(__name__)

import time
import random
import requests
from urllib.parse import quote
from django.http import JsonResponse
from django.views import View
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

class DorkSearchView(View):
    SEARCH_ENGINES = [
        {
            'name': 'duckduckgo',
            'url': 'https://duckduckgo.com/html/?q={query}',
            'parser': 'parse_duckduckgo',
            'throttle': 3
        },
        {
            'name': 'bing',
            'url': 'https://www.bing.com/search?q={query}',
            'parser': 'parse_bing',
            'throttle': 5
        }
    ]

    def get(self, request):
        dork_query = request.GET.get('dork', '').strip()
        amount = int(request.GET.get('amount', 10))
        
        if not dork_query:
            return JsonResponse({'success': False, 'error': 'Empty search query', 'results': []}, status=400)
        
        try:
            for engine in self.SEARCH_ENGINES:
                try:
                    time.sleep(random.uniform(engine['throttle'], engine['throttle'] + 2))
                    results = self.search_engine(engine, dork_query, amount)
                    if results:
                        return JsonResponse({'success': True, 'results': results[:amount], 'source': engine['name']})
                except Exception as e:
                    print(f"Search failed with {engine['name']}: {str(e)}")
                    continue
            
            return JsonResponse({'success': False, 'error': 'All search attempts failed', 'results': []})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e), 'results': []})

    def get_random_headers(self):
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0'
        ]
        return {'User-Agent': random.choice(user_agents)}

    def search_engine(self, engine, query, num):
        try:
            url = engine['url'].format(query=quote(query))
            html = self.fetch_with_selenium(url)
            parser_method = getattr(self, engine['parser'])
            return parser_method(html, num)
        except Exception as e:
            print(f"Error searching with {engine['name']}: {str(e)}")
            raise

    def fetch_with_selenium(self, url):
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        time.sleep(random.uniform(2, 5))
        html = driver.page_source
        driver.quit()
        return html

    def parse_duckduckgo(self, html, num):
        try:
            soup = BeautifulSoup(html, 'html.parser')
            results = []
            for result in soup.select('.result__body')[:num]:
                try:
                    title = result.select_one('.result__title').get_text().strip()
                    link = result.select_one('.result__url')['href']
                    snippet = result.select_one('.result__snippet').get_text().strip() if result.select_one('.result__snippet') else ''
                    results.append({'title': title, 'link': link, 'snippet': snippet})
                except:
                    continue
            return results
        except Exception as e:
            print(f"Error parsing DuckDuckGo results: {str(e)}")
            return []

    def parse_bing(self, html, num):
        try:
            soup = BeautifulSoup(html, 'html.parser')
            results = []
            for result in soup.select('.b_algo')[:num]:
                try:
                    title = result.select_one('h2 a').get_text().strip()
                    link = result.select_one('h2 a')['href']
                    snippet = result.select_one('.b_caption p').get_text().strip() if result.select_one('.b_caption p') else ''
                    results.append({'title': title, 'link': link, 'snippet': snippet})
                except:
                    continue
            return results
        except Exception as e:
            print(f"Error parsing Bing results: {str(e)}")
            return []


            
from django.http import StreamingHttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
import requests
import json

@method_decorator(csrf_exempt, name='dispatch')
class SingleImageDownloadView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            url = data.get('url')
            
            if not url:
                return JsonResponse({'error': 'URL is required'}, status=400)
            
            # Stream the image from the source
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            # Forward the streamed response
            return StreamingHttpResponse(
                response.iter_content(chunk_size=8192),
                content_type=response.headers['Content-Type'],
                status=response.status_code
            )
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)




#Exploit
import socket
import dns.resolver
import nmap
import requests
import re
import whois
from datetime import datetime
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

class ScanView(APIView):
    def post(self, request):
        ip = request.data.get("ip")
        
        if not ip:
            return Response(
                {"error": "IP address is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not self.validate_ip(ip):
            return Response(
                {"error": "Invalid IP address format"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Basic host information
            hostname = self.get_hostname(ip)
            
            # Get IP information from ip-api.com (free tier)
            ip_api_data = self.get_ip_api_info(ip)
            
            # Port scanning
            ports = self.scan_ports(ip)
            
            # DNS information
            dns_info = self.get_dns_info(ip)
            
            # WHOIS information
            whois_info = self.get_whois_info(ip)
            
            # Threat intelligence (mock data)
            threat_info = {
                "is_tor": False,
                "is_proxy": False,
                "is_vpn": False
            }
            
            # Check for known vulnerabilities
            vulnerabilities = self.check_vulnerabilities(ip, ports)
            
            return Response({
                "ip": ip,
                "hostname": hostname,
                "isp": ip_api_data.get("isp"),
                "organization": ip_api_data.get("org"),
                "location": {
                    "city": ip_api_data.get("city"),
                    "region": ip_api_data.get("regionName"),
                    "country": ip_api_data.get("country"),
                    "postal": ip_api_data.get("zip"),
                    "timezone": ip_api_data.get("timezone"),
                    "lat": ip_api_data.get("lat"),
                    "lon": ip_api_data.get("lon"),
                },
                "asn": {
                    "asn": ip_api_data.get("as"),
                    "name": ip_api_data.get("asname"),
                    "route": ip_api_data.get("query"),
                },
                "ports": ports,
                "vulnerabilities": vulnerabilities,
                "dns": {
                    "mx": dns_info.get("mx"),
                    "ns": dns_info.get("ns"),
                },
                "whois": {
                    "registrar": whois_info.get("registrar"),
                    "creation_date": whois_info.get("creation_date"),
                },
                "threat": threat_info
            })
            
        except Exception as e:
            return Response(
                {"error": f"Failed to scan target: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def validate_ip(self, ip):
        """Validate IP address format"""
        pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(pattern, ip) is not None

    def get_hostname(self, ip):
        """Get reverse DNS hostname"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None

    def get_ip_api_info(self, ip):
        """Get information from ip-api.com"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {}

    def scan_ports(self, ip):
        """Scan for common open ports"""
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments='-F')  # Fast scan
            
            if ip not in nm.all_hosts():
                return []
                
            ports = []
            for proto in nm[ip].all_protocols():
                for port, info in nm[ip][proto].items():
                    ports.append({
                        "port": port,
                        "protocol": proto,
                        "state": info['state'],
                        "service": info['name'],
                        "version": info.get('product', '') + ' ' + info.get('version', '')
                    })
            return ports
        except:
            return []

    def get_dns_info(self, ip):
        """Get DNS records for the IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            resolver = dns.resolver.Resolver()
            
            mx_records = []
            try:
                answers = resolver.resolve(hostname, 'MX')
                mx_records = [str(r.exchange) for r in answers]
            except:
                pass
                
            ns_records = []
            try:
                answers = resolver.resolve(hostname, 'NS')
                ns_records = [str(r.target) for r in answers]
            except:
                pass
                
            return {
                "mx": mx_records if mx_records else None,
                "ns": ns_records if ns_records else None
            }
        except:
            return {}

    def get_whois_info(self, ip):
        """Get WHOIS information"""
        try:
            w = whois.whois(ip)
            
            def format_date(date):
                if isinstance(date, list):
                    return date[0].strftime('%Y-%m-%d') if date else None
                elif date:
                    return date.strftime('%Y-%m-%d')
                return None
                
            return {
                "registrar": w.registrar,
                "creation_date": format_date(w.creation_date)
            }
        except:
            return {}

    def check_vulnerabilities(self, ip, ports):
        """Check for common vulnerabilities based on open ports"""
        vulnerabilities = []
        
        # SSH vulnerabilities
        if any(p['port'] == 22 and p['state'] == 'open' for p in ports):
            vulnerabilities.append({
                "name": "SSH Service Exposure",
                "severity": "high",
                "description": "SSH port (22) is open and may be vulnerable to brute force attacks.",
                "cve": "CVE-2018-15473"
            })
        
        # RDP vulnerabilities
        if any(p['port'] == 3389 and p['state'] == 'open' for p in ports):
            vulnerabilities.append({
                "name": "RDP Service Exposure",
                "severity": "high",
                "description": "RDP port (3389) is open and may be vulnerable to exploits like BlueKeep.",
                "cve": "CVE-2019-0708"
            })
        
        # HTTP vulnerabilities
        if any(p['port'] == 80 and p['state'] == 'open' for p in ports):
            vulnerabilities.append({
                "name": "HTTP Service Exposure",
                "severity": "medium",
                "description": "HTTP port (80) is open. Web applications may contain vulnerabilities.",
                "cve": None
            })
        
        # SMB vulnerabilities
        if any(p['port'] == 445 and p['state'] == 'open' for p in ports):
            vulnerabilities.append({
                "name": "SMB Service Exposure",
                "severity": "critical",
                "description": "SMB port (445) is open and may be vulnerable to EternalBlue.",
                "cve": "CVE-2017-0144"
            })
        
        return vulnerabilities

#---------------------------------------
#RAZORPAY
#--------------------------------------

from decimal import Decimal
import razorpay
import json
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from django.utils import timezone
from django.conf import settings
from .models import UserSubscription
from rest_framework.views import APIView

logger = logging.getLogger(__name__)

class RazorpayService:
    client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

    @staticmethod
    def verify_payment(payment_id, order_id, signature):
        try:
            params_dict = {
                'razorpay_order_id': order_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': signature
            }
            RazorpayService.client.utility.verify_payment_signature(params_dict)
            return True
        except razorpay.errors.SignatureVerificationError:
            return False

@method_decorator(csrf_exempt, name='dispatch')
class ProcessSubscriptionView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body.decode("utf-8"))
            user_id = data.get('user_id')
            payment_id = data.get('payment_id')
            signature = data.get('signature')

            if not all([user_id, payment_id, signature]):
                return JsonResponse(
                    {'success': False, 'message': 'Missing parameters'}, 
                    status=400
                )

            # Verify payment with Razorpay
            payment = RazorpayService.client.payment.fetch(payment_id)
            if not RazorpayService.verify_payment(
                payment_id, 
                payment['order_id'], 
                signature
            ):
                return JsonResponse(
                    {'success': False, 'message': 'Payment verification failed'}, 
                    status=400
                )

            # Create or update subscription
            user_sub, created = UserSubscription.objects.get_or_create(
                user_id=user_id,
                defaults={
                    'payment_id': payment_id,
                    'status': 'active',
                    'amount': Decimal(payment['amount'])/100
                }
            )
            
            if not created:
                user_sub.payment_id = payment_id
                user_sub.status = 'active'
                user_sub.amount = Decimal(payment['amount'])/100
                user_sub.save()

            return JsonResponse({
                'success': True, 
                'message': 'Subscription activated successfully'
            })

        except Exception as e:
            logger.error(f"Error processing subscription: {str(e)}")
            return JsonResponse(
                {'success': False, 'message': str(e)}, 
                status=500
            )

@method_decorator(csrf_exempt, name='dispatch')
class CheckAccessView(View):
    def get(self, request, *args, **kwargs):
        try:
            user_id = request.GET.get('user_id')
            if not user_id:
                return JsonResponse(
                    {'access': False, 'reason': 'user_id required'}, 
                    status=400
                )

            user_sub, created = UserSubscription.objects.get_or_create(
                user_id=user_id,
                defaults={
                    'status': 'trial',
                    'subscription_id': 'sub_QDRfqjnj567L55'
                }
            )

            if user_sub.is_valid():
                return JsonResponse({
                    'access': True,
                    'is_trial': user_sub.status == 'trial',
                    'trial_ends': user_sub.trial_end.isoformat() if user_sub.status == 'trial' else None,
                    'status': user_sub.status
                })

            return JsonResponse({
                'access': False,
                'reason': 'subscription_required',
                'message': 'Please subscribe to access premium features'
            })

        except Exception as e:
            logger.error(f"Error checking access: {str(e)}")
            return JsonResponse(
                {'access': False, 'reason': 'server_error'}, 
                status=500
            )
        

# Crawler

from decimal import Decimal
import razorpay
import json
import logging
import requests
import hashlib
import hmac

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from django.utils import timezone
from django.conf import settings
from rest_framework.views import APIView

from .models import UserSubscription
from .scraper import scrape_page_content, search_web

logger = logging.getLogger(__name__)

# -------------------------------
# ✅ Razorpay Service
# -------------------------------
class RazorpayService:
    client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

    @staticmethod
    def verify_payment(payment_id, order_id, signature):
        try:
            params_dict = {
                'razorpay_order_id': order_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': signature
            }
            RazorpayService.client.utility.verify_payment_signature(params_dict)
            return True
        except razorpay.errors.SignatureVerificationError:
            return False

    @staticmethod
    def create_subscription(user_id, email):
        try:
            subscription = RazorpayService.client.subscription.create({
                "plan_id": settings.RAZORPAY_PLAN_ID,
                "total_count": 12,  # 1 year subscription
                "customer_notify": 1,
                "notes": {
                    "user_id": user_id,
                    "email": email
                }
            })
            return subscription
        except Exception as e:
            logger.error(f"Subscription creation failed: {str(e)}")
            raise

# -------------------------------
# ✅ Webhook Handler
# -------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class RazorpayWebhookView(View):
    def post(self, request, *args, **kwargs):
        try:
            payload = request.body.decode('utf-8')
            received_signature = request.headers.get('X-Razorpay-Signature')
            
            expected_signature = hmac.new(
                key=settings.RAZORPAY_WEBHOOK_SECRET.encode('utf-8'),
                msg=payload.encode('utf-8'),
                digestmod=hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(received_signature, expected_signature):
                logger.error("Webhook signature verification failed")
                return JsonResponse({'status': 'error', 'message': 'Invalid signature'}, status=400)

            event = json.loads(payload)
            logger.info(f"Webhook event: {event.get('event')}")

            # Handle subscription events
            if event.get('event') in ['subscription.charged', 'payment.captured']:
                payment = event.get('payload', {}).get('payment', {}).get('entity', {})
                subscription_id = payment.get('subscription_id')
                user_id = payment.get('notes', {}).get('user_id')
                
                if user_id and subscription_id:
                    try:
                        user_sub = UserSubscription.objects.get(user_id=user_id)
                        user_sub.status = 'active'
                        user_sub.subscription_id = subscription_id
                        user_sub.save()
                        logger.info(f"Subscription activated for user {user_id}")
                    except UserSubscription.DoesNotExist:
                        logger.error(f"User subscription not found for user_id: {user_id}")
                        # Create new subscription if not exists
                        UserSubscription.objects.create(
                            user_id=user_id,
                            status='active',
                            subscription_id=subscription_id,
                            trial_end=timezone.now() + timezone.timedelta(days=365)
                        )
            
            return JsonResponse({'status': 'success'})
            
        except Exception as e:
            logger.error(f"Webhook processing error: {str(e)}")
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

# -------------------------------
# ✅ Subscription Views
# -------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class CreateSubscriptionView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body.decode("utf-8"))
            user_id = data.get("user_id")
            email = data.get("email", "user@odin.com")
            
            if not user_id:
                return JsonResponse({'success': False, 'message': 'User ID required'}, status=400)

            subscription = RazorpayService.create_subscription(user_id, email)
            
            return JsonResponse({
                'success': True,
                'subscription_id': subscription.get('id'),
                'status': subscription.get('status'),
                'subscription_link': settings.RAZORPAY_SUBSCRIPTION_LINK1,
                'redirect_url': f"{settings.RAZORPAY_SUBSCRIPTION_LINK1}?subscription_id={subscription.get('id')}"
            })

        except Exception as e:
            logger.error(f"Subscription error: {str(e)}")
            return JsonResponse({'success': False, 'message': str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class SubscriptionStatusView(APIView):
    def get(self, request, user_id):
        try:
            sub = UserSubscription.objects.get(user_id=user_id)
            return JsonResponse({
                'status': sub.status,
                'subscription_id': sub.subscription_id,
                'is_active': sub.is_valid(),
                'trial_end': sub.trial_end.isoformat() if sub.trial_end else None
            })
        except UserSubscription.DoesNotExist:
            return JsonResponse({'error': 'No subscription found'}, status=404)

# ... [Keep all your existing views like CheckAccessView, CrawlView, etc.] ...

# -------------------------------
# ✅ Check Access View (Updated)
# -------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class CheckAccessView1(View):
    def get(self, request, *args, **kwargs):
        try:
            user_id = int(request.GET.get('user_id'))
        except (TypeError, ValueError):
            return JsonResponse({'access': False, 'reason': 'Invalid user_id'}, status=400)

        try:
            # Set default trial_end for new users
            user_sub, created = UserSubscription.objects.get_or_create(
                user_id=user_id,
                defaults={
                    'status': 'trial',
                    'trial_end': timezone.now() + timezone.timedelta(days=3)
                }
            )

            # Check if trial has expired
            if user_sub.status == 'trial' and user_sub.trial_end < timezone.now():
                user_sub.status = 'expired'
                user_sub.save()
                return JsonResponse({
                    'access': False,
                    'is_trial': False,
                    'reason': 'trial_expired',
                    'message': 'Your trial has expired. Please subscribe to continue.'
                })

            if user_sub.is_valid():
                return JsonResponse({
                    'access': True,
                    'is_trial': user_sub.status == 'trial',
                    'trial_ends': user_sub.trial_end.isoformat() if user_sub.status == 'trial' else None,
                    'status': user_sub.status
                })

            return JsonResponse({
                'access': False,
                'reason': 'subscription_required',
                'message': 'Please subscribe to access Odin Crawler'
            })

        except Exception as e:
            logger.error(f"Error in CheckAccessView: {str(e)}")
            return JsonResponse({'access': False, 'reason': 'internal_error'}, status=500)
# -------------------------------
# ✅ Subscription Management View
# -------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class SubscriptionManagementView(APIView):
    def get(self, request, user_id):
        try:
            sub = UserSubscription.objects.get(user_id=user_id)
            return JsonResponse({
                'status': sub.status,
                'plan': 'premium',
                'start_date': sub.created_at.isoformat(),
                'trial_end': sub.trial_end.isoformat() if sub.status == 'trial' else None,
                'is_active': sub.is_valid()
            })
        except UserSubscription.DoesNotExist:
            return JsonResponse({'error': 'No subscription found'}, status=404)

# -------------------------------
# ✅ CrawlView with Trial Enforcement
# -------------------------------
@method_decorator(csrf_exempt, name='dispatch')
class CrawlView(View):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body.decode("utf-8"))
            user_id = data.get("user_id")
            if not user_id:
                return JsonResponse({"status": "error", "error": "Missing user_id"}, status=400)

            try:
                user_sub = UserSubscription.objects.get(user_id=int(user_id))
            except UserSubscription.DoesNotExist:
                return JsonResponse({"status": "error", "error": "User not registered"}, status=400)
            
            if not user_sub.is_valid():
                return JsonResponse({
                    "status": "error", 
                    "error": "Trial expired or no valid subscription.",
                    "requires_payment": True
                }, status=403)

            if "keyword" in data and data["keyword"].strip():
                keyword = data["keyword"].strip()
                links = search_web(keyword)

                # Apply limits based on subscription status
                if user_sub.status == 'trial':
                    extracted_data = {"links": links[:20]}  # Trial limit
                else:
                    extracted_data = {"links": links}       # Full access

                title = f"Results for keyword: {keyword}"

            elif "url" in data and data["url"].strip():
                url = data["url"].strip()
                extracted_data = scrape_page_content(url)
                title = f"Results for URL: {url}"

            else:
                return JsonResponse({
                    "status": "error", 
                    "error": "Please provide a keyword or URL."
                }, status=400)

            if not extracted_data:
                return JsonResponse({
                    "status": "error", 
                    "error": "No data extracted."
                }, status=400)

            return JsonResponse({
                "status": "success", 
                "title": title, 
                **extracted_data
            }, status=200)

        except json.JSONDecodeError as e:
            logger.error("JSON Decode Error: %s", str(e))
            return JsonResponse({
                "status": "error", 
                "error": "Invalid JSON format"
            }, status=400)
        except Exception as e:
            logger.error("Unexpected Error: %s", str(e))
            return JsonResponse({
                "status": "error", 
                "error": str(e)
            }, status=500)
        
@method_decorator(csrf_exempt, name='dispatch')
class CreateRazorpayOrderView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body.decode("utf-8"))
            user_id = data.get("user_id")
            amount = data.get("amount", 0.012)  # Default amount ₹1
            
            if not user_id:
                return JsonResponse({'success': False, 'message': 'User ID required'}, status=400)

            # Create Razorpay order
            order = RazorpayService.client.order.create({
                'amount': int(float(amount) * 100),  # Convert to paise
                'currency': 'INR',
                'receipt': f'order_{user_id}_{int(time.time())}',
                'notes': {
                    'user_id': user_id
                }
            })

            return JsonResponse({
                'success': True,
                'order_id': order.get('id'),
                'amount': order.get('amount'),
                'currency': order.get('currency'),
                'key': settings.RAZORPAY_KEY_ID
            })

        except Exception as e:
            logger.error(f"Order creation error: {str(e)}")
            return JsonResponse({'success': False, 'message': str(e)}, status=500)        