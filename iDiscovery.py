#!/usr/bin/env python3

import socket
import platform
import subprocess
import ipaddress
import threading
import time
import sys
import os
import re
import logging
from datetime import datetime

# Importa resource apenas em sistemas compatíveis (Linux/Unix)
if platform.system().lower() != 'windows':
    import resource
    # Configuração de recursos do sistema
    try:
        # Aumenta o limite de arquivos abertos
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    except:
        pass

from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, sr1, RandShort, conf, get_if_list, get_if_addr

# Configuração de logging
logging.basicConfig(
    level=logging.ERROR,  # Mudado para ERROR para remover INFO
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('iDiscovery.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Configura o logging para suprimir avisos do Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

# Configurações de timeout e performance
DEFAULT_TIMEOUT = 0.5  # Timeout padrão para scans
UBIQUITI_TIMEOUT = 1.0  # Timeout reduzido para scan Ubiquiti
TCP_SYN_TIMEOUT = 0.5  # Timeout para TCP SYN scan
UDP_BUFFER_SIZE = 1024
UBIQUITI_MAX_RETRIES = 1  # Reduzido para 1 tentativa
BATCH_SIZE = {
    'default': 128,   # Scan padrão: lotes maiores
    'tcp_syn': 64,    # TCP SYN: lotes médios
    'ubiquiti': 32    # Ubiquiti: lotes menores mas mais frequentes
}
WORKER_MULTIPLIER = {
    'default': 8,     # Scan padrão: mais workers
    'tcp_syn': 6,     # TCP SYN: workers médios
    'ubiquiti': 4     # Ubiquiti: menos workers
}
MAX_CONCURRENT_BATCHES = 4  # Aumentado para melhor paralelismo

# Arte ASCII
ASCII_ART = r"""
                                       
 _ ____  _                             
|_|    \|_|___ ___ ___ _ _ ___ ___ _ _ 
| |  |  | |_ -|  _| . | | | -_|  _| | |
|_|____/|_|___|___|___|\_/|___|_| |_  |
                                  |___|
"""

# Portas comuns para escaneamento rápido
FAST_PORTS = [80, 443, 22]  # HTTP, HTTPS, SSH
# Portas adicionais para escaneamento completo
FULL_PORTS = [20, 21, 23, 25, 53, 110, 143, 445, 993, 995, 3306, 3389, 8080]
# Porta específica para dispositivos Ubiquiti
UBIQUITI_PORT = 10001

# Pacotes de descoberta Ubiquiti atualizados
UBIQUITI_DISCOVERY_PACKETS = [
    b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # Pacote básico
    b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # Pacote alternativo
    b'\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # Pacote de descoberta estendido
    b'\x01\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   # Pacote de descoberta adicional
]

def get_local_ip():
    """Obtém o IP local da máquina"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None

def get_network_range(ip, cidr=None):
    """Obtém o range de IPs da rede local"""
    try:
        network = ipaddress.IPv4Network(f"{ip}/{cidr or 24}", strict=False)
        return network
    except Exception:
        return None

def get_arp_table():
    """Obtém a tabela ARP do sistema"""
    arp_table = {}
    try:
        if platform.system().lower() == 'windows':
            # Primeiro tenta atualizar a tabela ARP fazendo ping para a rede
            try:
                local_ip = get_local_ip()
                if local_ip:
                    network = get_network_range(local_ip)
                    if network:
                        # Faz ping para o gateway e broadcast
                        gateway = str(network[1])  # Primeiro IP útil
                        broadcast = str(network[-1])  # Último IP útil
                        subprocess.run(['ping', '-n', '1', '-w', '100', gateway], 
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        subprocess.run(['ping', '-n', '1', '-w', '100', broadcast], 
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass

            # Obtém a tabela ARP atualizada
            output = subprocess.check_output(['arp', '-a'], text=True, timeout=2)
            for line in output.split('\n'):
                # Procura por linhas que contenham IPs e MACs
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                # Aceita tanto o formato com hífen quanto com dois pontos
                mac_match = re.search(r'([0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2})', line.lower())
                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(1)
                    # Normaliza o MAC para usar hífen
                    mac = mac.replace(':', '-')
                    # Ignora MACs inválidos
                    if mac != "ff-ff-ff-ff-ff-ff" and mac != "00-00-00-00-00-00":
                        arp_table[ip] = mac
        else:
            # No Linux/Unix, primeiro tenta atualizar a tabela ARP
            try:
                local_ip = get_local_ip()
                if local_ip:
                    network = get_network_range(local_ip)
                    if network:
                        gateway = str(network[1])
                        broadcast = str(network[-1])
                        subprocess.run(['ping', '-c', '1', '-W', '1', gateway], 
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        subprocess.run(['ping', '-c', '1', '-W', '1', broadcast], 
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass

            # Obtém a tabela ARP atualizada
            output = subprocess.check_output(['arp', '-n'], text=True, timeout=2)
            for line in output.split('\n'):
                if 'ether' in line.lower():
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[0]
                        mac = parts[2]
                        # Normaliza o MAC para usar hífen
                        mac = mac.replace(':', '-')
                        # Ignora MACs inválidos
                        if mac != "ff-ff-ff-ff-ff-ff" and mac != "00-00-00-00-00-00":
                            arp_table[ip] = mac
    except Exception as e:
        logging.error(f"Erro ao obter tabela ARP: {e}")
    return arp_table

def update_arp_table(ip):
    """Tenta atualizar a tabela ARP para um IP específico"""
    try:
        if platform.system().lower() == 'windows':
            subprocess.run(['ping', '-n', '1', '-w', '100', str(ip)], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

def check_port(ip, port, protocol='tcp', timeout=1):
    """Verifica se uma porta está aberta"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            
            if protocol == 'tcp':
                result = sock.connect_ex((str(ip), port))
                return result == 0
            else:  # udp
                try:
                    sock.sendto(b'', (str(ip), port))
                    sock.recvfrom(UDP_BUFFER_SIZE)
                    return True
                except:
                    return False
    except:
        return False

def scan_host_tcp_syn(ip, ports=None, iface=None, timeout=TCP_SYN_TIMEOUT):
    """Escaneia um host usando TCP SYN scan"""
    if ports is None:
        ports = FAST_PORTS
    
    try:
        ip_str = str(ip)
        original_iface = conf.iface
        
        if iface:
            try:
                conf.iface = iface
            except:
                pass
        
        try:
            valid_responses = 0
            required_responses = 2
            
            # Envia cada pacote individualmente para evitar problemas com RandShort
            for port in ports:
                try:
                    # Cria e envia um pacote por vez
                    packet = IP(dst=ip_str)/TCP(dport=port, flags="S", sport=RandShort())
                    response = sr1(packet, timeout=timeout, verbose=0)
                    
                    if response is not None and response.haslayer(TCP):
                        # Verifica se é uma resposta SYN-ACK (0x12)
                        if response[TCP].flags == 0x12 or response[TCP].flags == 0x14:
                            valid_responses += 1
                            if valid_responses >= required_responses:
                                return True, None
                except Exception as e:
                    # Não imprime erro para timeout
                    continue
            
            return False, None
        finally:
            if iface:
                conf.iface = original_iface
    except Exception:
        return False, None

def scan_host_ubiquiti(ip, timeout=UBIQUITI_TIMEOUT):
    """Escaneia um host específico para dispositivos Ubiquiti usando UDP"""
    try:
        ip_str = str(ip)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            
            # Contador de respostas válidas
            valid_responses = 0
            required_responses = 1  # Precisa de pelo menos 1 resposta válida
            
            # Envia os pacotes com pequeno delay entre eles
            for packet in UBIQUITI_DISCOVERY_PACKETS:
                try:
                    # Envia o pacote
                    sock.sendto(packet, (ip_str, UBIQUITI_PORT))
                    
                    # Tenta receber resposta com timeout reduzido
                    try:
                        data, addr = sock.recvfrom(UDP_BUFFER_SIZE)
                        
                        # Verifica se a resposta veio do IP correto E da porta UDP 10001
                        if addr[0] == ip_str and addr[1] == UBIQUITI_PORT:
                            # Verifica se a resposta tem tamanho mínimo
                            if data and len(data) >= 4:
                                # Verifica se é uma resposta válida (primeiro byte deve ser 0x02)
                                if data[0] == 0x02:
                                    valid_responses += 1
                                    if valid_responses >= required_responses:
                                        return True, None
                    except socket.timeout:
                        continue
                    except ConnectionResetError:
                        continue
                    except Exception as e:
                        continue
                    
                    # Pequeno delay entre tentativas
                    time.sleep(0.01)
                    
                except ConnectionResetError:
                    continue
                except Exception as e:
                    continue
            
            return False, None
    except Exception as e:
        return False, None

def scan_host_default(ip_str, fast_mode=True):
    """Escaneia um host usando o método padrão (ping + portas)"""
    try:
        # Verifica portas essenciais
        ports_to_check = FAST_PORTS if fast_mode else FAST_PORTS + FULL_PORTS
        valid_responses = 0
        required_responses = 2
        
        with ThreadPoolExecutor(max_workers=min(len(ports_to_check), 10)) as executor:
            futures = [executor.submit(check_port, ip_str, port) for port in ports_to_check]
            for future in as_completed(futures):
                if future.result():
                    valid_responses += 1
                    if valid_responses >= required_responses:
                        return True, None
                        # break não é necessário pois já retorna
        return False, None
    except Exception as e:
        logging.error(f"Erro no scan padrão de {ip_str}: {e}")
        return False, None

def scan_host(ip_str, arp_table, fast_mode=True, scan_method='default', iface=None):
    """Escaneia um host específico usando o método escolhido"""
    try:
        # Para scan Ubiquiti, ignora a tabela ARP e verifica apenas a porta UDP 10001
        if scan_method == 'ubiquiti':
            return scan_host_ubiquiti(ip_str)
        
        # Para outros métodos, verifica primeiro na tabela ARP
        if ip_str in arp_table:
            mac = arp_table[ip_str]
            if mac and mac != "00-00-00-00-00-00" and mac != "ff-ff-ff-ff-ff-ff":
                return True, mac
        
        # Escolhe o método de escaneamento
        if scan_method == 'tcp_syn':
            return scan_host_tcp_syn(ip_str, iface)
        else:
            return scan_host_default(ip_str, fast_mode)
            
    except Exception as e:
        logging.error(f"Erro ao escanear {ip_str}: {e}")
        return False, None

def print_progress(current, total, batch=False):
    """Imprime uma barra de progresso (atualiza menos se batch=True)"""
    if batch and current % 10 != 0 and current != total:
        return
    progress = (current / total) * 100
    bar_length = 50
    filled_length = int(bar_length * current / total)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    sys.stdout.write(f'\rEscaneando: [{bar}] {progress:.1f}% ({current}/{total})')
    sys.stdout.flush()

def scan_network(fast_mode=True, target_ip=None, cidr=None, scan_method='default', iface=None):
    """Escaneia a rede local usando o método escolhido"""
    print(ASCII_ART)
    
    # Configurações específicas por método
    method_configs = {
        'ubiquiti': {
            'batch_delay': 0.1,
            'update_interval': 0.05,
            'progress_threshold': 0.1,
            'max_concurrent': 16
        },
        'tcp_syn': {
            'batch_delay': 0.05,
            'update_interval': 0.05,
            'progress_threshold': 0.1,
            'max_concurrent': 32
        },
        'default': {
            'batch_delay': 0.02,
            'update_interval': 0.05,
            'progress_threshold': 0.1,
            'max_concurrent': 64
        }
    }
    
    config = method_configs[scan_method]
    
    # Configura logging para ERROR apenas
    logging.getLogger().setLevel(logging.ERROR)
    
    if scan_method == 'ubiquiti':
        print("Método: Ubiquiti (UDP 10001)")
    elif scan_method == 'tcp_syn':
        print("Método: TCP SYN")
        if iface:
            print(f"Interface: {iface}")
    else:
        print("Método: Padrão (ping + portas)")
    
    if target_ip is None:
        local_ip = get_local_ip()
        if not local_ip:
            return
        target_ip = local_ip
        network = get_network_range(target_ip, cidr)
    else:
        network = ipaddress.IPv4Network(f"{target_ip}/{cidr or 32}", strict=False)
    
    if not network:
        return
    
    print(f"Rede: {network}")
    print("Obtendo tabela ARP...")
    arp_table = get_arp_table()
    
    print("\nEscaneando...")
    sys.stdout.flush()
    
    active_ips = []
    ip_list = list(network.hosts())
    total_ips = len(ip_list)
    processed_ips = 0
    stop_event = threading.Event()
    
    try:
        batch_size = BATCH_SIZE[scan_method]
        cpu_count = os.cpu_count() or 2
        max_workers = min(batch_size * 2, cpu_count * WORKER_MULTIPLIER[scan_method] * 2)
        
        print(f"Usando {max_workers} workers em lotes de {batch_size} IPs\n")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            active_batches = 0
            max_concurrent_batches = 4
            
            for i in range(0, len(ip_list), batch_size):
                if stop_event.is_set():
                    break
                
                # Processa os resultados dos lotes anteriores
                done_futures = [f for f in futures if f.done()]
                for future in done_futures:
                    try:
                        is_active, mac = future.result()
                        if is_active:
                            ip = futures[future]
                            active_ips.append((ip, mac))
                    except Exception as e:
                        if not stop_event.is_set():
                            print(f"\nErro ao escanear IP: {e}")
                    finally:
                        del futures[future]
                        active_batches -= 1
                        processed_ips += 1
                        print_progress(processed_ips, total_ips, batch=True)
                
                # Aguarda se houver muitos lotes ativos
                while active_batches >= max_concurrent_batches:
                    time.sleep(0.05)
                    active_batches = sum(1 for f in futures if not f.done())
                
                batch = ip_list[i:i + batch_size]
                if not batch:
                    continue
                
                batch_futures = {
                    executor.submit(scan_host, str(ip), arp_table, fast_mode, scan_method, iface): str(ip)
                    for ip in batch
                }
                futures.update(batch_futures)
                active_batches += 1
                
                if scan_method == 'ubiquiti':
                    time.sleep(0.02)
                elif scan_method == 'tcp_syn':
                    time.sleep(0.01)
            
            # Processa os lotes restantes
            for future in list(futures.keys()):
                if not stop_event.is_set():
                    try:
                        is_active, mac = future.result()
                        if is_active:
                            ip = futures[future]
                            active_ips.append((ip, mac))
                    except Exception as e:
                        if not stop_event.is_set():
                            print(f"\nErro ao escanear IP: {e}")
                    finally:
                        processed_ips += 1
                        print_progress(processed_ips, total_ips, batch=True)
        
        print("\n\nIPs ativos encontrados:\n")
        
        if not active_ips:
            print("Nenhum dispositivo encontrado na rede.")
            return
        
        # Ordena e exibe os IPs ativos
        active_ips.sort(key=lambda x: [int(i) for i in x[0].split('.')])
        print("\nDispositivos encontrados:")
        print("IP              | MAC Address")
        print("-" * 35)
        for ip, mac in active_ips:
            mac_str = mac if mac else "N/A"
            print(f"{ip:<15} | {mac_str}")
    
    except KeyboardInterrupt:
        print("\nEscaneamento interrompido.")
        stop_event.set()
    except Exception as e:
        print(f"\nErro: {e}")
        if scan_method in ['tcp_syn', 'ubiquiti']:
            print("Dica: Execute como administrador/root.")

def validate_ip(ip):
    """Valida se um IP é válido"""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def get_default_interface():
    """Obtém a interface de rede padrão em uso"""
    try:
        # Obtém o IP local
        local_ip = get_local_ip()
        if not local_ip:
            return None

        # Lista todas as interfaces
        interfaces = get_if_list()
        
        # Para cada interface, verifica se tem o IP local
        for iface in interfaces:
            try:
                if_addr = get_if_addr(iface)
                if if_addr and local_ip in if_addr:
                    return iface
            except:
                continue
        
        # Se não encontrou por IP, tenta usar a interface padrão do sistema
        if platform.system().lower() == 'windows':
            # No Windows, tenta encontrar a primeira interface que não seja loopback
            for iface in interfaces:
                if iface != 'lo' and not iface.startswith('lo'):
                    return iface
        else:
            # No Linux/Unix, tenta encontrar a primeira interface que não seja loopback
            for iface in interfaces:
                if iface != 'lo' and not iface.startswith('lo'):
                    return iface
        
        return None
    except Exception as e:
        print(f"Erro ao detectar interface de rede: {e}")
        return None

if __name__ == "__main__":
    try:
        start_time = datetime.now()
        logging.info("Iniciando iDiscovery")
        
        print(ASCII_ART)
        print("Escolha o modo de escaneamento:")
        print("1. Escanear rede local automaticamente")
        print("2. Escanear IP/CIDR")
        print("3. Escanear IP específico")
        
        while True:
            try:
                opcao = int(input("\nDigite sua opção (1-3): "))
                if opcao in [1, 2, 3]:
                    break
                print("Opção inválida! Digite 1, 2 ou 3.")
            except ValueError:
                print("Digite apenas números!")
        
        print("\nEscolha o método de escaneamento:")
        print("1. Método padrão (ping + portas)")
        print("2. TCP SYN scan")
        print("3. Scan Ubiquiti (UDP 10001)")
        
        while True:
            try:
                metodo = int(input("\nDigite o método (1-3): "))
                if metodo in [1, 2, 3]:
                    break
                print("Opção inválida! Digite 1, 2 ou 3.")
            except ValueError:
                print("Digite apenas números!")
        
        scan_method = 'ubiquiti' if metodo == 3 else ('tcp_syn' if metodo == 2 else 'default')
        iface = None
        
        if scan_method == 'tcp_syn':
            iface = get_default_interface()
            if iface:
                print(f"\nInterface de rede detectada automaticamente: {iface}")
                use_auto = input("Deseja usar esta interface? (S/n): ").lower() != 'n'
                if not use_auto:
                    iface = input("\nDigite o nome da interface de rede (ex: eth0, wlan0): ")
            else:
                print("\nNão foi possível detectar a interface automaticamente.")
                iface = input("Digite o nome da interface de rede (ex: eth0, wlan0): ")
            
            if not iface:
                print("Nenhuma interface especificada. O escaneamento pode não funcionar corretamente.")
        
        if opcao == 1:
            logging.info("Iniciando scan automático da rede local")
            scan_network(fast_mode=True, scan_method=scan_method, iface=iface)
        elif opcao == 2:
            while True:
                try:
                    entrada = input("\nDigite o IP/CIDR: ")
                    ip, cidr = entrada.split('/')
                    cidr = int(cidr)
                    if cidr < 16:
                        print("CIDR muito pequeno! Use um valor entre 16 e 32.")
                        continue
                    if cidr > 32:
                        print("CIDR muito grande! Use um valor entre 16 e 32.")
                        continue
                    break
                except ValueError:
                    print("Formato inválido! Use o formato IP/CIDR (exemplo: 192.168.1.0/24)")
            logging.info(f"Iniciando scan do IP/CIDR {ip}/{cidr}")
            scan_network(fast_mode=True, target_ip=ip, cidr=cidr, scan_method=scan_method, iface=iface)
        else:  # opcao == 3
            while True:
                try:
                    ip = input("\nDigite o IP para escanear: ")
                    if validate_ip(ip):
                        break
                    print("IP inválido! Digite um IP válido.")
                except ValueError:
                    print("IP inválido! Digite um IP válido.")
            logging.info(f"Iniciando scan do IP específico {ip}")
            scan_network(fast_mode=True, target_ip=ip, scan_method=scan_method, iface=iface)
            
        end_time = datetime.now()
        duration = end_time - start_time
        logging.info(f"Scan concluído em {duration.total_seconds():.2f} segundos")
            
    except KeyboardInterrupt:
        logging.info("Scan interrompido pelo usuário")
        print("\n\nScan interrompido pelo usuário.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Erro fatal: {e}", exc_info=True)
        print(f"\nErro fatal: {e}")
        sys.exit(1)