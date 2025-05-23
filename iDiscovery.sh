#!/bin/bash

# Cores para o terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função para verificar se um comando existe
command_exists() {
    command -v "$1" &> /dev/null
}

# Função para instalar dependências do sistema
install_system_deps() {
    if command_exists apt-get; then
        echo "Instalando dependências do sistema (Debian/Ubuntu)..."
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-venv
    elif command_exists dnf; then
        echo "Instalando dependências do sistema (Fedora)..."
        sudo dnf install -y python3 python3-pip python3-virtualenv
    elif command_exists yum; then
        echo "Instalando dependências do sistema (RHEL/CentOS)..."
        sudo yum install -y python3 python3-pip python3-virtualenv
    else
        echo -e "${RED}Gerenciador de pacotes não suportado!${NC}"
        echo "Por favor, instale manualmente:"
        echo "- Python 3"
        echo "- pip3"
        echo "- python3-venv ou python3-virtualenv"
        exit 1
    fi
}

echo -e "${GREEN}iDiscovery - Network Scanner${NC}"
echo "Verificando dependências..."

# Verifica se o Python está instalado
if ! command_exists python3; then
    echo -e "${YELLOW}Python 3 não encontrado!${NC}"
    install_system_deps
fi

# Verifica se o pip está instalado
if ! command_exists pip3; then
    echo -e "${YELLOW}pip3 não encontrado!${NC}"
    install_system_deps
fi

# Verifica se o módulo venv está disponível
if ! python3 -c "import venv" &> /dev/null; then
    echo -e "${YELLOW}Módulo venv não encontrado!${NC}"
    install_system_deps
fi

# Verifica se está rodando como root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Este programa requer privilégios de root para escanear a rede.${NC}"
    echo -e "${YELLOW}Por favor, insira sua senha quando solicitado.${NC}"
    # Executa o script novamente como root, mas mantém o ambiente do usuário
    exec sudo -E "$0" "$@"
fi

# Verifica se o ambiente virtual existe, se não, cria
if [ ! -d "venv" ]; then
    echo "Criando ambiente virtual..."
    python3 -m venv venv
    
    # Ativa o ambiente virtual e instala as dependências
    source venv/bin/activate
    echo "Instalando dependências do requirements.txt..."
    pip install --upgrade pip
    pip install -r requirements.txt
    deactivate
fi

# Ativa o ambiente virtual
source venv/bin/activate

# Executa o scanner com o ambiente virtual ativado
echo -e "${GREEN}Iniciando o scanner...${NC}"
python3 iDiscovery.py

# Verifica se houve erro na execução
if [ $? -ne 0 ]; then
    echo -e "${RED}Erro ao executar o scanner!${NC}"
    deactivate
    exit 1
fi

# Desativa o ambiente virtual ao sair
deactivate