# iDiscovery

Ferramenta de descoberta de dispositivos na rede local.

## Estado Atual

A implementação ativa foi migrada para C#/.NET em `src/iDiscovery`.

## Funcionalidades

- Descobre o IP local e a rede padrão automaticamente
- Escaneia uma rede inteira via `IP/CIDR`
- Escaneia um IP específico
- Faz consulta da tabela ARP para identificar MAC address
- Suporta varredura por:
  - método padrão com ping e portas TCP
  - TCP connect scan
  - descoberta Ubiquiti via UDP 10001
- Executa varredura paralela para acelerar a busca
- Exibe barra de progresso e lista final de hosts ativos

## Requisitos

- .NET SDK 10.0 ou superior
- Acesso à rede local
- Privilégios de administrador/root podem ser necessários para alguns cenários de rede

## Como executar

```bash
dotnet run --project src/iDiscovery
```

## Uso via argumentos

```bash
dotnet run --project src/iDiscovery -- --mode auto --scan default
dotnet run --project src/iDiscovery -- --mode cidr --target 192.168.1.0/24 --scan tcp
dotnet run --project src/iDiscovery -- --mode ip --target 192.168.1.10 --scan ubiquiti
```

Opções principais:

- `--mode auto|cidr|ip`
- `--target <valor>`
- `--scan default|tcp|ubiquiti`
- `--fast true|false`
- `--help`

## Como compilar

```bash
dotnet build src/iDiscovery
```

## Estrutura

- `iDiscovery.sln`
- `src/iDiscovery/Program.cs`
- `src/iDiscovery/ConsoleApp.cs`
- `src/iDiscovery/NetworkScanner.cs`
- `src/iDiscovery/Models.cs`
- `src/iDiscovery/ScanInputParser.cs`
- `src/iDiscovery/Ipv4Network.cs`
- `src/iDiscovery/IpAddressComparer.cs`
- `src/iDiscovery/iDiscovery.csproj`

## Observações

- O modo "TCP connect" substitui a antiga abordagem baseada em pacotes crus, para manter a solução sem dependências externas.
- Em ambientes com firewall agressivo, alguns hosts podem não responder ao ping ou às portas testadas.
