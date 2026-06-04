namespace iDiscovery;

internal sealed record CommandLineOptions(
    bool ShowHelp,
    bool IsInteractive,
    TargetMode? Mode,
    ScanMethod? Method,
    string? Target,
    bool FastMode)
{
    public static CommandLineOptions Parse(string[] args)
    {
        if (args.Length == 0)
        {
            return new CommandLineOptions(
                ShowHelp: false,
                IsInteractive: true,
                Mode: null,
                Method: null,
                Target: null,
                FastMode: true);
        }

        var targetMode = (TargetMode?)null;
        var scanMethod = (ScanMethod?)null;
        string? target = null;
        var fastMode = true;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (IsHelpArg(arg))
            {
                return new CommandLineOptions(true, false, null, null, null, true);
            }

            if (TryGetValue(arg, args, ref i, out var value))
            {
                switch (NormalizeOptionName(arg))
                {
                    case "mode":
                        targetMode = ParseTargetMode(value);
                        if (targetMode is null)
                        {
                            throw new ArgumentException($"Valor inválido para --mode: {value}");
                        }
                        break;
                    case "scan":
                        scanMethod = ParseScanMethod(value);
                        if (scanMethod is null)
                        {
                            throw new ArgumentException($"Valor inválido para --scan: {value}");
                        }
                        break;
                    case "target":
                        target = value;
                        break;
                    case "fast":
                        if (!bool.TryParse(value, out fastMode))
                        {
                            throw new ArgumentException($"Valor inválido para --fast: {value}");
                        }
                        break;
                    default:
                        throw new ArgumentException($"Opção desconhecida: {arg}");
                }

                continue;
            }

            throw new ArgumentException($"Argumento inválido: {arg}");
        }

        return new CommandLineOptions(false, false, targetMode, scanMethod, target, fastMode);
    }

    private static bool IsHelpArg(string arg)
        => arg is "-h" or "--help" or "-?";

    private static bool TryGetValue(string arg, string[] args, ref int index, out string value)
    {
        value = string.Empty;

        var normalized = NormalizeOptionName(arg);
        if (normalized is not ("mode" or "scan" or "target" or "fast"))
        {
            return false;
        }

        if (arg.Contains('='))
        {
            var split = arg.Split('=', 2);
            value = split.Length == 2 ? split[1] : string.Empty;
            return true;
        }

        if (index + 1 >= args.Length)
        {
            throw new ArgumentException($"Falta valor para {arg}");
        }

        value = args[++index];
        return true;
    }

    private static string NormalizeOptionName(string arg)
    {
        var name = arg;
        if (name.StartsWith("--", StringComparison.Ordinal))
        {
            name = name[2..];
        }
        else if (name.StartsWith("-", StringComparison.Ordinal))
        {
            name = name[1..];
        }

        var eqIndex = name.IndexOf('=');
        if (eqIndex >= 0)
        {
            name = name[..eqIndex];
        }

        return name.ToLowerInvariant() switch
        {
            "m" => "mode",
            "s" => "scan",
            "t" => "target",
            "f" => "fast",
            _ => name.ToLowerInvariant()
        };
    }

    private static TargetMode? ParseTargetMode(string value)
    {
        return value.ToLowerInvariant() switch
        {
            "auto" => global::iDiscovery.TargetMode.Auto,
            "cidr" => global::iDiscovery.TargetMode.Cidr,
            "ip" => global::iDiscovery.TargetMode.SingleIp,
            _ => null
        };
    }

    private static ScanMethod? ParseScanMethod(string value)
    {
        return value.ToLowerInvariant() switch
        {
            "default" => global::iDiscovery.ScanMethod.Default,
            "tcp" or "tcpconnect" or "tcp-connect" => global::iDiscovery.ScanMethod.TcpConnect,
            "ubiquiti" => global::iDiscovery.ScanMethod.Ubiquiti,
            _ => null
        };
    }
}
