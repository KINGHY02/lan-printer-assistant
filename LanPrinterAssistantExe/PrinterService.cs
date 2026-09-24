using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace LanPrinterAssistant;

internal sealed class PrinterService
{
    public IReadOnlyList<string> GetLocalPrinters() => NativePrinter.LocalPrinters();
    public bool Share(string printer, string shareName) => NativePrinter.Share(printer, shareName);
    public bool GrantEveryonePrintPermission(string printer) => NativePrinter.GrantEveryonePrintPermission(printer);
    public bool Unshare(string printer) => NativePrinter.Unshare(printer);
    public bool Exists(string printer) => NativePrinter.Exists(printer);
    public bool AddConnection(string unc) => NativePrinter.AddConnection(unc);
    public bool AddConnectionWithWindowsFallback(string unc, out int errorCode)
    {
        if (NativePrinter.AddConnection(unc)) { errorCode = 0; return true; }
        errorCode = Marshal.GetLastWin32Error();
        try
        {
            using var process = Process.Start(new ProcessStartInfo("rundll32.exe", $"printui.dll,PrintUIEntry /in /n \"{unc}\"") { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden });
            process?.WaitForExit(15000);
        }
        catch { }
        return NativePrinter.Exists(unc);
    }
}
