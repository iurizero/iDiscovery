using System.Net;

namespace iDiscovery;

internal enum TargetMode
{
    Auto,
    Cidr,
    SingleIp
}

internal enum ScanMethod
{
    Default,
    TcpConnect,
    Ubiquiti
}

internal sealed record ScanTarget(IPAddress? Address, int? Cidr);

internal sealed record ScanResult(IPAddress Address, string? MacAddress);
