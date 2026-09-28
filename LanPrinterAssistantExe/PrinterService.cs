using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace LanPrinterAssistant;

internal sealed class PrinterService
{
    public IReadOnlyList<string> GetLocalPrinters() => NativePrinter.LocalPrinters();
    public bool ShareWithWindowsFallback(string printer, string shareName, out int errorCode)
    {
        if (NativePrinter.Share(printer, shareName)) { errorCode = 0; return true; }
        errorCode = Marshal.GetLastWin32Error();
        try
        {
            // Some legacy USB drivers reject SetPrinter(PRINTER_INFO_2), but
            // still support the same operation through Windows PrintUI.
            var start = new ProcessStartInfo("rundll32.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            start.ArgumentList.Add("printui.dll,PrintUIEntry");
            start.ArgumentList.Add("/Xs");
            start.ArgumentList.Add("/n");
            start.ArgumentList.Add(printer);
            start.ArgumentList.Add("Shared");
            start.ArgumentList.Add("true");
            start.ArgumentList.Add("ShareName");
            start.ArgumentList.Add(shareName);
            using var process = Process.Start(start);
            if (process != null)
            {
                process.WaitForExit(15000);
                if (process.ExitCode == 0) { errorCode = 0; return true; }
                errorCode = process.ExitCode;
            }
        }
        catch { }
        return false;
    }
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
