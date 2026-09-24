using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace LanPrinterAssistant;

internal sealed class NetworkService
{
    public async Task<bool> TestPortAsync(string address, int port, CancellationToken token = default)
    {
        try
        {
            using var client = new TcpClient();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(450);
            await client.ConnectAsync(address, port, timeout.Token);
            return true;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch { return false; }
    }

    public async Task<bool> PingAsync(string address, CancellationToken token = default)
    {
        try
        {
            using var ping = new Ping();
            return (await ping.SendPingAsync(address, 500).WaitAsync(token)).Status == IPStatus.Success;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch { return false; }
    }

    public async Task<string> GetPrinterSharesAsync(string address, CancellationToken token = default)
    {
        try { return await Task.Run(() => NativePrinter.PrintShares(address), token).WaitAsync(TimeSpan.FromSeconds(1.2), token); }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch { return ""; }
    }

    public async Task<ScanResult> InspectAsync(string address, CancellationToken token = default)
    {
        var result = new ScanResult
        {
            Ip = address,
            Ping = await PingAsync(address, token),
            Smb = await TestPortAsync(address, 445, token),
            Raw = await TestPortAsync(address, 9100, token),
            Ipp = await TestPortAsync(address, 631, token)
        };
        if (result.Smb) result.Shares = await GetPrinterSharesAsync(address, token);
        return result;
    }

    public static IReadOnlyList<LanAddress> ActiveLanAddresses() => NetworkInfo.AllLanAddresses();
}
