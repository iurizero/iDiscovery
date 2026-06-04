using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace iDiscovery;

internal sealed class NetworkScanner
{
    private static readonly int[] FastPorts = [80, 443, 22];
    private static readonly int[] FullPorts = [20, 21, 23, 25, 53, 110, 143, 445, 993, 995, 3306, 3389, 8080];
    private static readonly byte[][] UbiquitiDiscoveryPackets =
    [
        [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    ];

    private static readonly Regex IpRegex = new(@"\b(?<ip>(?:\d{1,3}\.){3}\d{1,3})\b", RegexOptions.Compiled);
    private static readonly Regex MacRegex = new(@"\b(?<mac>(?:[0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2})\b", RegexOptions.Compiled);

    private readonly CancellationTokenSource _cancellation = new();

    public void RequestCancellation() => _cancellation.Cancel();

    public async Task<IReadOnlyList<ScanResult>> ScanNetworkAsync(
        IPAddress? targetAddress,
        int? cidr,
        ScanMethod method,
        bool fastMode,
        CancellationToken cancellationToken = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cancellation.Token);

        var effectiveTarget = targetAddress ?? GetLocalIpAddress();
        if (effectiveTarget is null)
        {
            return Array.Empty<ScanResult>();
        }

        var prefix = cidr ?? (targetAddress is null ? 24 : 32);
        var network = Ipv4Network.Create(effectiveTarget, prefix);

        Console.WriteLine();
        Console.WriteLine($"Método: {DescribeMethod(method)}");

        Console.WriteLine($"Rede: {network}");
        Console.WriteLine("Obtendo tabela ARP...");

        var arpTable = await GetArpTableAsync(linked.Token);

        Console.WriteLine();
        Console.WriteLine("Escaneando...");

        var hosts = network.GetHosts().ToList();
        var active = new ConcurrentBag<ScanResult>();
        var processed = 0;
        var total = hosts.Count;
        var maxWorkers = GetMaxDegreeOfParallelism(method);

        Console.WriteLine($"Usando {maxWorkers} workers em {total} IPs");

        await Parallel.ForEachAsync(
            hosts,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = maxWorkers,
                CancellationToken = linked.Token
            },
            async (host, ct) =>
            {
                var result = await ScanHostAsync(host, arpTable, fastMode, method, ct);
                if (result is not null && result.Value.IsActive)
                {
                    active.Add(new ScanResult(host, result.Value.MacAddress));
                }

                var current = Interlocked.Increment(ref processed);
                if (current % 10 == 0 || current == total)
                {
                    PrintProgress(current, total);
                }
            });

        Console.WriteLine();
        return active.ToArray();
    }

    private static string DescribeMethod(ScanMethod method)
    {
        return method switch
        {
            ScanMethod.Ubiquiti => "Ubiquiti (UDP 10001)",
            ScanMethod.TcpConnect => "TCP connect",
            _ => "Padrão (ping + portas TCP)"
        };
    }

    private static int GetMaxDegreeOfParallelism(ScanMethod method)
    {
        return method switch
        {
            ScanMethod.Ubiquiti => Environment.ProcessorCount * 4,
            ScanMethod.TcpConnect => Environment.ProcessorCount * 6,
            _ => Environment.ProcessorCount * 8
        };
    }

    private static void PrintProgress(int current, int total)
    {
        var percent = total == 0 ? 100 : (current * 100.0) / total;
        var width = 36;
        var filled = total == 0 ? width : (int)Math.Round(width * current / (double)total);
        filled = Math.Clamp(filled, 0, width);

        var bar = new string('█', filled) + new string('░', width - filled);
        Console.Write($"\rEscaneando: [{bar}] {percent,5:F1}% ({current}/{total})");
    }

    private async Task<(bool IsActive, string? MacAddress)?> ScanHostAsync(
        IPAddress address,
        IReadOnlyDictionary<string, string> arpTable,
        bool fastMode,
        ScanMethod method,
        CancellationToken cancellationToken)
    {
        var ip = address.ToString();

        if (method == ScanMethod.Ubiquiti)
        {
            var isUbiquiti = await ScanUbiquitiAsync(address, cancellationToken);
            return isUbiquiti ? (true, null) : (false, null);
        }

        if (arpTable.TryGetValue(ip, out var mac) && !IsInvalidMac(mac))
        {
            return (true, mac);
        }

        if (method == ScanMethod.TcpConnect)
        {
            var tcp = await ScanTcpConnectAsync(address, cancellationToken);
            return tcp ? (true, null) : (false, null);
        }

        var ping = await PingAsync(address);
        if (ping)
        {
            return (true, null);
        }

        var ports = fastMode ? FastPorts : FastPorts.Concat(FullPorts).ToArray();
        foreach (var port in ports)
        {
            var open = await IsTcpPortOpenAsync(address, port, 650, cancellationToken);
            if (open)
            {
                return (true, null);
            }
        }

        return (false, null);
    }

    private static bool IsInvalidMac(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac))
        {
            return true;
        }

        var normalized = mac.Replace(':', '-').ToLowerInvariant();
        return normalized is "ff-ff-ff-ff-ff-ff" or "00-00-00-00-00-00";
    }

    private static async Task<bool> PingAsync(IPAddress address)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(address, 500, Array.Empty<byte>(), new PingOptions(64, true));
            return reply.Status == IPStatus.Success;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> ScanTcpConnectAsync(IPAddress address, CancellationToken cancellationToken)
    {
        var ports = FastPorts;
        var success = 0;

        foreach (var port in ports)
        {
            if (await IsTcpPortOpenAsync(address, port, 650, cancellationToken))
            {
                success++;
                if (success >= 1)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static async Task<bool> IsTcpPortOpenAsync(IPAddress address, int port, int timeoutMs, CancellationToken cancellationToken)
    {
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            var connectTask = client.ConnectAsync(address, port);
            var timeoutTask = Task.Delay(timeoutMs, cancellationToken);
            var completed = await Task.WhenAny(connectTask, timeoutTask);
            return completed == connectTask && client.Connected;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> ScanUbiquitiAsync(IPAddress address, CancellationToken cancellationToken)
    {
        try
        {
            using var udp = new UdpClient(address.AddressFamily);
            udp.Client.ReceiveTimeout = 1000;
            udp.Client.SendTimeout = 1000;

            foreach (var packet in UbiquitiDiscoveryPackets)
            {
                cancellationToken.ThrowIfCancellationRequested();

                await udp.SendAsync(packet, packet.Length, new IPEndPoint(address, 10001));

                var receiveTask = udp.ReceiveAsync();
                var timeoutTask = Task.Delay(1000, cancellationToken);
                var completed = await Task.WhenAny(receiveTask, timeoutTask);

                if (completed == receiveTask)
                {
                    var response = await receiveTask;
                    if (response.RemoteEndPoint.Address.Equals(address) &&
                        response.RemoteEndPoint.Port == 10001 &&
                        response.Buffer.Length >= 4 &&
                        response.Buffer[0] == 0x02)
                    {
                        return true;
                    }
                }
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    private static async Task<IReadOnlyDictionary<string, string>> GetArpTableAsync(CancellationToken cancellationToken)
    {
        var table = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var outputs = new List<string>();

        foreach (var command in GetArpCommands())
        {
            var output = await RunCommandAsync(command.FileName, command.Arguments, cancellationToken);
            if (!string.IsNullOrWhiteSpace(output))
            {
                outputs.Add(output);
            }
        }

        foreach (var output in outputs)
        {
            foreach (var line in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                var ipMatch = IpRegex.Match(line);
                var macMatch = MacRegex.Match(line);
                if (!ipMatch.Success || !macMatch.Success)
                {
                    continue;
                }

                var ip = ipMatch.Groups["ip"].Value;
                var mac = macMatch.Groups["mac"].Value.Replace(':', '-');
                if (!IsInvalidMac(mac))
                {
                    table[ip] = mac;
                }
            }
        }

        return table;
    }

    private static IEnumerable<(string FileName, string Arguments)> GetArpCommands()
    {
        if (OperatingSystem.IsWindows())
        {
            yield return ("arp", "-a");
            yield break;
        }

        yield return ("arp", "-n");
        yield return ("ip", "neigh");
    }

    private static async Task<string?> RunCommandAsync(string fileName, string arguments, CancellationToken cancellationToken)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return null;
            }

            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync(cancellationToken);

            var output = await outputTask;
            var error = await errorTask;
            return string.IsNullOrWhiteSpace(output) ? error : output;
        }
        catch
        {
            return null;
        }
    }

    private static IPAddress? GetLocalIpAddress()
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect("8.8.8.8", 80);
            if (socket.LocalEndPoint is IPEndPoint endPoint)
            {
                return endPoint.Address;
            }
        }
        catch
        {
            // Fallback below.
        }

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            foreach (var address in nic.GetIPProperties().UnicastAddresses)
            {
                if (address.Address.AddressFamily == AddressFamily.InterNetwork &&
                    !IPAddress.IsLoopback(address.Address))
                {
                    return address.Address;
                }
            }
        }

        return null;
    }
}
