#!/bin/bash

# Cores para o terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}iDiscovery - Network Scanner${NC}"
echo "Verificando dependências..."

# Verifica se o Python está instalado
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 não encontrado!${NC}"
    echo "Por favor, instale o Python 3:"
    echo "sudo apt-get install python3"
    exit 1
fi

# Verifica se está rodando como root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Este programa requer privilégios de root para escanear a rede.${NC}"
    echo -e "${YELLOW}Por favor, insira sua senha quando solicitado.${NC}"
    sudo "$0" "$@"
    exit $?
fi

# Executa o scanner
echo -e "${GREEN}Iniciando o scanner...${NC}"
python3 iDiscovery.py

# Verifica se houve erro na execução
if [ $? -ne 0 ]; then
    echo -e "${RED}Erro ao executar o scanner!${NC}"
    exit 1
fi