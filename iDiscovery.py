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
from concurrent.futures import ThreadPoolExecutor

# Arte ASCII
ASCII_ART = r"""
                                       
 _ ____  _                             
|_|    \|_|___ ___ ___ _ _ ___ ___ _ _ 
| |  |  | |_ -|  _| . | | | -_|  _| | |
|_|____/|_|___|___|___|\_/|___|_| |_  |
                                  |___|
"""

def get_local_ip():
    """Obtém o IP local da máquina"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Erro ao obter IP local: {e}")
        print("Verifique sua conexão de rede e firewall.")
        return None

def get_network_range(ip, cidr=None):
    """Obtém o range de IPs da rede local"""
    try:
        if cidr is None:
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        else:
            network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
        return network
    except Exception as e:
        print(f"Erro ao calcular range de rede: {e}")
        print("Verifique se o IP e CIDR estão corretos.")
        return None

def get_arp_table():
    """Obtém a tabela ARP do sistema"""
    arp_table = {}
    try:
        if platform.system().lower() == 'windows':
            output = subprocess.check_output(['arp', '-a'], text=True)
            for line in output.split('\n'):
                if 'dynamic' in line.lower():
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    mac_match = re.search(r'([0-9a-f]{2}(?:-[0-9a-f]{2}){5})', line.lower())
                    if ip_match and mac_match:
                        arp_table[ip_match.group(1)] = mac_match.group(1)
        else:
            output = subprocess.check_output(['arp', '-n'], text=True)
            for line in output.split('\n'):
                if 'ether' in line.lower():
                    parts = line.split()
                    if len(parts) >= 3:
                        arp_table[parts[0]] = parts[2]
    except Exception as e:
        print(f"Erro ao obter tabela ARP: {e}")
    return arp_table

def check_port(ip, port, protocol='tcp'):
    """Verifica se uma porta está aberta"""
    try:
        if protocol == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:  # udp
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        sock.settimeout(1)
        if protocol == 'tcp':
            result = sock.connect_ex((str(ip), port))
            sock.close()
            return result == 0
        else:  # udp
            try:
                sock.sendto(b'', (str(ip), port))
                sock.recvfrom(1024)
                return True
            except:
                return False
            finally:
                sock.close()
    except:
        return False

def scan_host(ip, arp_table, fast_mode=True):
    """Escaneia um host específico"""
    try:
        ip_str = str(ip)
        
        # Verifica se o IP está na tabela ARP
        if ip_str in arp_table:
            return True, arp_table[ip_str]
        
        # Tenta ping com timeout aumentado
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout = '1000' if platform.system().lower() == 'windows' else '1'
        command = ['ping', param, '1', '-w', timeout, ip_str]
        try:
            subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=2)
            return True, None
        except:
            pass
        
        # Verifica apenas as portas mais essenciais
        essential_ports = [
            (80, 'tcp'),    # HTTP
            (10001, 'udp')  # Ubiquiti
        ]
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(check_port, ip, port, protocol) for port, protocol in essential_ports]
            for future in futures:
                if future.result():
                    return True, None
        
        # Se não estiver no modo rápido, verifica portas adicionais
        if not fast_mode:
            additional_ports = [
                (443, 'tcp'),   # HTTPS
                (22, 'tcp')     # SSH
            ]
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(check_port, ip, port, protocol) for port, protocol in additional_ports]
                for future in futures:
                    if future.result():
                        return True, None
        
        return False, None
    except Exception as e:
        return False, None

def print_progress(current, total):
    """Imprime uma barra de progresso"""
    progress = (current / total) * 100
    bar_length = 50
    filled_length = int(bar_length * current / total)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    sys.stdout.write(f'\rEscaneando: [{bar}] {progress:.1f}% ({current}/{total})')
    sys.stdout.flush()

def scan_network(fast_mode=True, target_ip=None, cidr=None):
    """Escaneia a rede local"""
    print(ASCII_ART)
    print("Iniciando escaneamento da rede...\n")
    
    if target_ip is None:
        local_ip = get_local_ip()
        if not local_ip:
            return
        print(f"Seu IP local: {local_ip}")
        target_ip = local_ip
        network = get_network_range(target_ip, cidr)
    else:
        print(f"IP alvo: {target_ip}")
        # Se não foi especificado um CIDR, assume que é um IP específico
        if cidr is None:
            network = ipaddress.IPv4Network(f"{target_ip}/32", strict=False)
        else:
            network = get_network_range(target_ip, cidr)
    
    if not network:
        return
    
    print(f"Rede a ser escaneada: {network}")
    print("Obtendo tabela ARP...")
    arp_table = get_arp_table()
    
    print("Escaneando IPs...\n")
    print("Dica: Este processo pode demorar alguns minutos para redes grandes.")
    print("O programa está verificando portas comuns e tentando conexões TCP diretas.\n")
    
    active_ips = []
    total_ips = len(list(network.hosts()))
    processed_ips = 0
    
    try:
        # Divide os IPs em lotes para processamento
        batch_size = 16  # Reduzido para dar mais tempo para cada IP
        ip_list = list(network.hosts())
        
        for i in range(0, len(ip_list), batch_size):
            batch = ip_list[i:i + batch_size]
            with ThreadPoolExecutor(max_workers=batch_size) as executor:
                futures = {executor.submit(scan_host, ip, arp_table, fast_mode): ip for ip in batch}
                
                for future in futures:
                    is_active, mac = future.result()
                    if is_active:
                        ip = futures[future]
                        active_ips.append((str(ip), mac))
                    
                    processed_ips += 1
                    print_progress(processed_ips, total_ips)
        
        print("\n\nIPs ativos encontrados:\n")
        
        if not active_ips:
            print("Nenhum IP ativo encontrado na rede.")
            print("\nPossíveis causas:")
            print("1. Firewall bloqueando pings e portas")
            print("2. Rede muito lenta")
            print("3. Dispositivos configurados para não responder")
            print("4. Problemas de permissão (execute como administrador/root)")
            print("5. Tente executar o programa novamente")
            print("6. Tente usar um CIDR menor (ex: /16) para escanear uma rede maior")
            return
        
        # Ordena e exibe os IPs ativos
        active_ips.sort(key=lambda x: [int(i) for i in x[0].split('.')])
        for ip, mac in active_ips:
            print(f"IP: {ip} | Up")
    
    except KeyboardInterrupt:
        print("\n\nEscaneamento interrompido pelo usuário.")
    except Exception as e:
        print(f"\n\nErro durante o escaneamento: {e}")
        print("Verifique se você tem permissões de administrador/root.")

def validate_ip(ip):
    """Valida se um IP é válido"""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

if __name__ == "__main__":
    try:
        print(ASCII_ART)
        print("Escolha o modo de escaneamento:")
        print("1. Escanear rede local automaticamente")
        print("2. Escanear IP/CIDR específico")
        print("3. Escanear IP específico")
        
        while True:
            try:
                opcao = int(input("\nDigite sua opção (1-3): "))
                if opcao in [1, 2, 3]:
                    break
                print("Opção inválida! Digite 1, 2 ou 3.")
            except ValueError:
                print("Digite apenas números!")
        
        if opcao == 1:
            scan_network(fast_mode=True)
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
            scan_network(fast_mode=True, target_ip=ip, cidr=cidr)
        else:  # opcao == 3
            while True:
                try:
                    ip = input("\nDigite o IP para escanear: ")
                    if validate_ip(ip):
                        break
                    print("IP inválido! Digite um IP válido.")
                except ValueError:
                    print("IP inválido! Digite um IP válido.")
            scan_network(fast_mode=True, target_ip=ip)
            
    except Exception as e:
        print(f"Erro fatal: {e}")
        sys.exit(1)