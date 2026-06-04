namespace iDiscovery;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        return await new ConsoleApp().RunAsync(args);
    }
}
