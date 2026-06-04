using System.Net;

namespace iDiscovery;

internal sealed record Ipv4Network(IPAddress NetworkAddress, IPAddress BroadcastAddress, int PrefixLength)
{
    public static Ipv4Network Create(IPAddress address, int prefixLength)
    {
        if (prefixLength is < 0 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixLength));
        }

        var raw = ScanInputParser.IpToUInt32(address);
        var mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
        var network = raw & mask;
        var broadcast = network | ~mask;

        return new Ipv4Network(
            ScanInputParser.UInt32ToIp(network),
            ScanInputParser.UInt32ToIp(broadcast),
            prefixLength);
    }

    public IEnumerable<IPAddress> GetHosts()
    {
        var start = ScanInputParser.IpToUInt32(NetworkAddress);
        var end = ScanInputParser.IpToUInt32(BroadcastAddress);

        if (PrefixLength >= 31)
        {
            for (var current = start; current <= end; current++)
            {
                yield return ScanInputParser.UInt32ToIp(current);
            }

            yield break;
        }

        for (var current = start + 1; current < end; current++)
        {
            yield return ScanInputParser.UInt32ToIp(current);
        }
    }

    public override string ToString() => $"{NetworkAddress}/{PrefixLength}";
}
