using System.Net;

namespace iDiscovery;

internal sealed class ConsoleApp
{
    private readonly NetworkScanner _scanner = new();

    public async Task<int> RunAsync(string[] args)
    {
        var startedAt = DateTimeOffset.Now;
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            _scanner.RequestCancellation();
        };

        try
        {
            var options = CommandLineOptions.Parse(args);
            if (options.ShowHelp)
            {
                PrintUsage();
                return 0;
            }

            if (options.IsInteractive)
            {
                PrintBanner();
            }

            var targetMode = options.Mode;
            var scanMethod = options.Method;

            if (!options.IsInteractive)
            {
                if (targetMode is null)
                {
                    Console.WriteLine("Você precisa informar --mode quando usar argumentos.");
                    PrintUsage();
                    return 1;
                }

                if (scanMethod is null)
                {
                    Console.WriteLine("Você precisa informar --scan quando usar argumentos.");
                    PrintUsage();
                    return 1;
                }
            }
            else
            {
                targetMode ??= ReadTargetMode();
                scanMethod ??= ReadScanMethod();
            }

            var target = ResolveTarget(targetMode.Value, options.Target, options.IsInteractive);
            if (target is null)
            {
                Console.WriteLine("Nenhum alvo informado.");
                return 1;
            }

            var results = await _scanner.ScanNetworkAsync(
                target.Address,
                target.Cidr,
                scanMethod.Value,
                fastMode: options.FastMode);

            Console.WriteLine();
            Console.WriteLine("Dispositivos encontrados:");
            Console.WriteLine("IP              | MAC Address");
            Console.WriteLine(new string('-', 35));

            if (results.Count == 0)
            {
                Console.WriteLine("Nenhum dispositivo encontrado na rede.");
                return 0;
            }

            foreach (var result in results.OrderBy(r => r.Address, new IpAddressComparer()))
            {
                var mac = string.IsNullOrWhiteSpace(result.MacAddress) ? "N/A" : result.MacAddress;
                Console.WriteLine($"{result.Address,-15} | {mac}");
            }

            var duration = DateTimeOffset.Now - startedAt;
            Console.WriteLine();
            Console.WriteLine($"Concluído em {duration.TotalSeconds:F2} s.");
            return 0;
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine();
            Console.WriteLine("Escaneamento interrompido.");
            return 130;
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine();
            Console.WriteLine(ex.Message);
            PrintUsage();
            return 1;
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Console.WriteLine($"Erro fatal: {ex.Message}");
            return 1;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
Uso:
  iDiscovery [opções]

Opções:
  -h, --help                 Mostra esta ajuda
  -m, --mode <auto|cidr|ip>   Define o modo de alvo
  -t, --target <valor>        Define o alvo:
                               auto: não usa valor
                               cidr: IP/CIDR, ex. 192.168.1.0/24
                               ip: IP específico, ex. 192.168.1.10
  -s, --scan <default|tcp|ubiquiti>
                             Define o método de scan
  -f, --fast <true|false>    Ativa ou desativa modo rápido

Exemplos:
  iDiscovery
  iDiscovery --mode auto --scan default
  iDiscovery --mode cidr --target 192.168.1.0/24 --scan tcp
  iDiscovery --mode ip --target 192.168.1.10 --scan ubiquiti
""");
    }

    private static void PrintBanner()
    {
        Console.WriteLine("""
                                        
 _ ____  _                             
|_|    \|_|___ ___ ___ _ _ ___ ___ _ _ 
| |  |  | |_ -|  _| . | | | -_|  _| | |
|_|____/|_|___|___|___|\_/|___|_| |_  |
                                  |___|
""");

        Console.WriteLine("Escolha o modo de escaneamento:");
        Console.WriteLine("1. Escanear rede local automaticamente");
        Console.WriteLine("2. Escanear IP/CIDR");
        Console.WriteLine("3. Escanear IP específico");
    }

    private static ScanTarget? ResolveTarget(TargetMode targetMode, string? targetValue, bool interactive)
    {
        return targetMode switch
        {
            TargetMode.Auto => new ScanTarget(null, null),
            TargetMode.Cidr => ResolveCidrTarget(targetValue, interactive),
            TargetMode.SingleIp => ResolveSingleIpTarget(targetValue, interactive),
            _ => null
        };
    }

    private static ScanTarget? ResolveCidrTarget(string? targetValue, bool interactive)
    {
        if (!string.IsNullOrWhiteSpace(targetValue))
        {
            if (ScanInputParser.TryParseCidr(targetValue, out var networkAddress, out var cidr))
            {
                return new ScanTarget(networkAddress, cidr);
            }

            if (!interactive)
            {
                Console.WriteLine("Formato inválido para --target. Use IP/CIDR, por exemplo 192.168.1.0/24.");
                return null;
            }
        }

        while (true)
        {
            Console.Write("\nDigite o IP/CIDR: ");
            var input = Console.ReadLine();
            if (ScanInputParser.TryParseCidr(input, out var networkAddress, out var cidr))
            {
                return new ScanTarget(networkAddress, cidr);
            }

            Console.WriteLine("Formato inválido! Use IP/CIDR, por exemplo 192.168.1.0/24.");
        }
    }

    private static ScanTarget? ResolveSingleIpTarget(string? targetValue, bool interactive)
    {
        if (!string.IsNullOrWhiteSpace(targetValue))
        {
            if (IPAddress.TryParse(targetValue, out var ip))
            {
                return new ScanTarget(ip, 32);
            }

            if (!interactive)
            {
                Console.WriteLine("Formato inválido para --target. Use um IP válido, por exemplo 192.168.1.10.");
                return null;
            }
        }

        while (true)
        {
            Console.Write("\nDigite o IP para escanear: ");
            var input = Console.ReadLine();
            if (IPAddress.TryParse(input, out var ip))
            {
                return new ScanTarget(ip, 32);
            }

            Console.WriteLine("IP inválido! Digite um IP válido.");
        }
    }

    private static TargetMode ReadTargetMode()
    {
        while (true)
        {
            Console.Write("\nDigite sua opção (1-3): ");
            var input = Console.ReadLine();

            if (input == "1")
            {
                return TargetMode.Auto;
            }

            if (input == "2")
            {
                return TargetMode.Cidr;
            }

            if (input == "3")
            {
                return TargetMode.SingleIp;
            }

            Console.WriteLine("Opção inválida! Digite 1, 2 ou 3.");
        }
    }

    private static ScanMethod ReadScanMethod()
    {
        Console.WriteLine();
        Console.WriteLine("Escolha o método de escaneamento:");
        Console.WriteLine("1. Método padrão (ping + portas TCP)");
        Console.WriteLine("2. TCP connect scan");
        Console.WriteLine("3. Scan Ubiquiti (UDP 10001)");

        while (true)
        {
            Console.Write("\nDigite o método (1-3): ");
            var input = Console.ReadLine();

            if (input == "1")
            {
                return ScanMethod.Default;
            }

            if (input == "2")
            {
                return ScanMethod.TcpConnect;
            }

            if (input == "3")
            {
                return ScanMethod.Ubiquiti;
            }

            Console.WriteLine("Opção inválida! Digite 1, 2 ou 3.");
        }
    }

}
