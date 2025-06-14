
# BlueWatcher - Ferramenta Completa de Auditoria e Monitoramento para Kali Linux

## Descrição
BlueWatcher é uma ferramenta multiuso para pentest, monitoramento de rede e auditoria do sistema, criada para rodar no Kali Linux.  
Ela integra funcionalidades de scanner, sniffer, enumeração, verificação básica de vulnerabilidades e coleta de informações do sistema local.

---

## Funcionalidades

- Scan TCP/UDP avançado com Nmap  
- Captura de pacotes com tcpdump e conversão para texto via tshark  
- Enumeração detalhada de serviços HTTP, FTP, SSH, SMB  
- Teste básico de vulnerabilidades comuns (ex: Heartbleed) com testssl.sh  
- Coleta de processos, portas, usuários, info de rede e logs locais  
- Relatórios organizados em arquivos na pasta `bluewatcher_reports`  

---

## Requisitos

- Kali Linux atualizado  
- Permissões de root para captura e scan (use sudo)  
- Internet para baixar dependências no install.sh

---

## Instalação

1. Dê permissão de execução no script de instalação:  
```
chmod +x install.sh
```

2. Execute o instalador (requer internet e sudo):  
```
sudo ./install.sh
```

3. Aguarde a instalação das dependências e configuração.

---

## Uso

```
sudo ./bluewatcher.py scan <alvo> [--udp]
sudo ./bluewatcher.py sniff <interface> [segundos]
sudo ./bluewatcher.py enum <alvo>
sudo ./bluewatcher.py vuln <alvo>
sudo ./bluewatcher.py sysinfo
sudo ./bluewatcher.py help
```

Exemplo:

```
sudo ./bluewatcher.py scan 192.168.1.0/24 --udp
sudo ./bluewatcher.py sniff eth0 60
sudo ./bluewatcher.py enum 192.168.1.100
sudo ./bluewatcher.py vuln 192.168.1.100
sudo ./bluewatcher.py sysinfo
```

---

## Relatórios

Os relatórios gerados ficam na pasta `bluewatcher_reports` criada no diretório onde a ferramenta é executada.

---

## Expansão

Você pode expandir o BlueWatcher adicionando novos módulos de exploração, interfaces gráficas, análises automáticas, etc.

---

## Autor

SHASHIBUKAY.

---

## Aviso Legal

Use esta ferramenta apenas em redes e sistemas que você tem autorização para testar.

