#!/bin/bash
echo "[*] Atualizando repositórios..."
sudo apt update

echo "[*] Instalando dependências necessárias..."
sudo apt install -y python3 python3-pip nmap tcpdump tshark curl smbclient netcat-openbsd ftp testssl.sh

echo "[*] Instalando python packages..."
pip3 install --upgrade pip
pip3 install pybluez

echo "[*] Instalando testssl.sh (se não instalado)..."
if ! command -v testssl.sh &> /dev/null
then
    echo "[*] Baixando testssl.sh..."
    git clone https://github.com/drwetter/testssl.sh.git
    cd testssl.sh
    sudo make install
    cd ..
fi

echo "[*] Tudo pronto! Para rodar a ferramenta, execute:"
echo "sudo ./bluewatcher.py <comando> [argumentos]"
