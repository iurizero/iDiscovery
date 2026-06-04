using System.Net;

namespace iDiscovery;

internal sealed class IpAddressComparer : IComparer<IPAddress>
{
    public int Compare(IPAddress? x, IPAddress? y)
    {
        if (x is null && y is null)
        {
            return 0;
        }

        if (x is null)
        {
            return -1;
        }

        if (y is null)
        {
            return 1;
        }

        var left = ScanInputParser.IpToUInt32(x);
        var right = ScanInputParser.IpToUInt32(y);
        return left.CompareTo(right);
    }
}
