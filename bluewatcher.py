#!/usr/bin/env python3
import subprocess
import sys
import os
from datetime import datetime

REPORT_DIR = "./bluewatcher_reports"

def run_cmd(cmd):
    print(f"[+] Executando: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] Erro ao executar comando: {e}")
        return ""

def scan_network(target, udp=False):
    print(f"\n[*] Escaneando rede alvo: {target} {'(UDP)' if udp else '(TCP)'}")
    base_cmd = ['nmap', '-sS', '-sV', '-O', '-T4']
    if udp:
        base_cmd = ['nmap', '-sU', '-T4']
    cmd = base_cmd + [target]
    output = run_cmd(cmd)
    save_report("network_scan.txt", output)

def sniff_packets(interface, duration=30):
    print(f"\n[*] Capturando pacotes na interface {interface} por {duration} segundos...")
    pcap_file = f"{REPORT_DIR}/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    try:
        subprocess.run(['timeout', str(duration), 'tcpdump', '-i', interface, '-w', pcap_file], check=True)
        print(f"[+] Captura salva em: {pcap_file}")
        # Convertendo para texto com tshark se disponível
        if shutil.which('tshark'):
            txt_file = pcap_file.replace('.pcap', '.txt')
            subprocess.run(['tshark', '-r', pcap_file, '-V', '-O', 'tcp,http', '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.port', '-e', 'http.host', '-e', 'http.request.uri'], stdout=open(txt_file, 'w'))
            print(f"[+] Arquivo texto da captura gerado: {txt_file}")
    except subprocess.CalledProcessError:
        print("[!] Falha na captura de pacotes")

def enum_services(target):
    print(f"\n[*] Enumerando serviços comuns no alvo {target}")
    services = {
        "HTTP": 80,
        "HTTPS": 443,
        "FTP": 21,
        "SSH": 22,
        "SMB": 445
    }
    results = ""
    for name, port in services.items():
        print(f"  - Checando {name} na porta {port}...")
        cmd = ['nmap', '-p', str(port), target]
        output = run_cmd(cmd)
        results += output + "\n"
        # Testes de banner simples
        if name == "HTTP" or name == "HTTPS":
            try:
                proto = "https" if port == 443 else "http"
                banner = subprocess.check_output(['curl', '-Is', f'{proto}://{target}'], text=True)
                results += f"--- {name} Banner ---\n{banner}\n"
            except:
                pass
        elif name == "FTP":
            try:
                banner = subprocess.check_output(['timeout', '5', 'ftp', target], stderr=subprocess.STDOUT, text=True)
                results += f"--- FTP Banner ---\n{banner}\n"
            except:
                pass
        elif name == "SSH":
            try:
                banner = subprocess.check_output(['timeout', '5', 'nc', target, '22'], stderr=subprocess.STDOUT, text=True)
                results += f"--- SSH Banner ---\n{banner}\n"
            except:
                pass
        elif name == "SMB":
            try:
                banner = subprocess.check_output(['smbclient', '-L', f'//{target}', '-N'], stderr=subprocess.STDOUT, text=True)
                results += f"--- SMB Shares ---\n{banner}\n"
            except:
                pass
    save_report("services_enum.txt", results)

def vuln_check(target):
    print(f"\n[*] Checando vulnerabilidades simples no alvo {target}")
    results = ""
    # Exemplo: Check SSL Heartbleed
    try:
        print("  - Checando vulnerabilidade Heartbleed (SSL)...")
        output = subprocess.check_output(['testssl.sh', '--heartbleed', target], stderr=subprocess.STDOUT, text=True)
        results += output + "\n"
    except Exception as e:
        results += f"Erro testssl.sh: {e}\n"
    save_report("vuln_check.txt", results)

def system_info():
    print("\n[*] Coletando informações do sistema local...")
    info = ""
    cmds = {
        "Processos": ["ps", "aux"],
        "Portas Abertas": ["ss", "-tuln"],
        "Usuários logados": ["who"],
        "Informações de rede": ["ip", "a"],
        "Rotas": ["ip", "r"],
        "Logs auth": ["tail", "-n", "20", "/var/log/auth.log"]
    }
    for desc, cmd in cmds.items():
        print(f"  - {desc}")
        output = run_cmd(cmd)
        info += f"\n=== {desc} ===\n{output}\n"
    save_report("system_info.txt", info)

def save_report(filename, content):
    os.makedirs(REPORT_DIR, exist_ok=True)
    path = os.path.join(REPORT_DIR, filename)
    with open(path, "w") as f:
        f.write(content)
    print(f"[+] Relatório salvo: {path}")

def usage():
    print("""Uso:
  bluewatcher.py scan <alvo> [--udp]           - Scan TCP/UDP com Nmap
  bluewatcher.py sniff <iface> [segundos]       - Sniffer de pacotes (default 30s)
  bluewatcher.py enum <alvo>                      - Enumeração básica de serviços
  bluewatcher.py vuln <alvo>                      - Check de vulnerabilidades simples
  bluewatcher.py sysinfo                          - Informações do sistema local
  bluewatcher.py help                             - Exibe essa ajuda
""")

def main():
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "scan":
        if len(sys.argv) < 3:
            print("[!] Alvo necessário para scan")
            sys.exit(1)
        udp = False
        if len(sys.argv) > 3 and sys.argv[3] == "--udp":
            udp = True
        scan_network(sys.argv[2], udp)

    elif cmd == "sniff":
        if len(sys.argv) < 3:
            print("[!] Interface de rede necessária para sniff")
            sys.exit(1)
        duration = 30
        if len(sys.argv) >= 4:
            try:
                duration = int(sys.argv[3])
            except:
                pass
        sniff_packets(sys.argv[2], duration)

    elif cmd == "enum":
        if len(sys.argv) < 3:
            print("[!] Alvo necessário para enumeração")
            sys.exit(1)
        enum_services(sys.argv[2])

    elif cmd == "vuln":
        if len(sys.argv) < 3:
            print("[!] Alvo necessário para check de vulnerabilidades")
            sys.exit(1)
        vuln_check(sys.argv[2])

    elif cmd == "sysinfo":
        system_info()

    elif cmd == "help":
        usage()

    else:
        usage()

if __name__ == "__main__":
    import shutil
    main()
