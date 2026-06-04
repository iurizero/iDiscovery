using System.Net;

namespace iDiscovery;

internal static class ScanInputParser
{
    public static bool TryParseCidr(string? input, out IPAddress address, out int cidr)
    {
        address = IPAddress.None;
        cidr = 0;

        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var parts = input.Split('/', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2)
        {
            return false;
        }

        if (!IPAddress.TryParse(parts[0], out var parsedAddress))
        {
            return false;
        }

        address = parsedAddress;

        if (!int.TryParse(parts[1], out cidr))
        {
            return false;
        }

        return cidr is >= 16 and <= 32;
    }

    public static uint IpToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return BitConverter.ToUInt32(bytes, 0);
    }

    public static IPAddress UInt32ToIp(uint value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return new IPAddress(bytes);
    }
}
