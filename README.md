# iDiscovery

Uma ferramenta simples para descobrir dispositivos na rede local, similar ao UBNT Discovery.

## Requisitos

- Python 3.6 ou superior
- Acesso à rede local
- Privilégios de administrador/root

## Como usar

### Linux/Mac

1. Dê permissão de execução ao script:
```bash
chmod +x iDiscovery.sh
```

2. Execute o script:
```bash
./iDiscovery.sh
```

O script criará automaticamente um atalho com ícone no menu de aplicativos.

### Windows

1. Clique duas vezes no arquivo `run_iDiscovery.bat`
2. Se solicitado, permita a execução como administrador

## Funcionalidades

- Compatível com Windows e Linux
- Descobre automaticamente sua rede local
- Escaneia todos os IPs na rede
- Mostra IPs ativos
- Escaneamento em paralelo para maior velocidade

## Observações

- O programa precisa de permissões de administrador/root para funcionar corretamente
- O tempo de escaneamento pode variar dependendo do tamanho da rede
- Alguns dispositivos podem não responder ao ping por configurações de firewall
- O ícone será aplicado automaticamente aos atalhos criados