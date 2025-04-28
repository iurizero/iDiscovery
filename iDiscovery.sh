#!/bin/bash

# Cores para o terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Cria o arquivo .desktop se não existir
if [ ! -f ~/.local/share/applications/iDiscovery.desktop ]; then
    echo -e "${YELLOW}Criando atalho com icone...${NC}"
    cat > ~/.local/share/applications/iDiscovery.desktop << EOL
[Desktop Entry]
Name=iDiscovery
Comment=Network Scanner Tool
Exec=$(pwd)/iDiscovery.sh
Icon=$(pwd)/iD icon.ico
Terminal=true
Type=Application
Categories=Utility;
EOL
    chmod +x ~/.local/share/applications/iDiscovery.desktop
fi

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
    echo -e "${YELLOW}Executando com privilégios de root...${NC}"
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