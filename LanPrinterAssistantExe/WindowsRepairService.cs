using Microsoft.Win32;

namespace LanPrinterAssistant;

internal sealed class WindowsRepairService
{
    public void ConfigurePrintRpc()
    {
        using var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC");
        key!.SetValue("RpcUseNamedPipeProtocol", 1, RegistryValueKind.DWord);
    }

    public void RestartPrintSpooler() => NativePrinter.RestartSpooler();
    public void EnablePrinterSharingFirewall() => NativePrinter.EnableFirewall();
    public void EnableGuestAccess() => NativePrinter.EnableGuest();
    public void RestoreGuestAccess((int? Workstation, int? Server) original) => NativePrinter.RestoreGuestSettings(original);
    public void ConfigureGuestClient()
    {
        // Windows 10/11 may reject a Guest printer connection unless the
        // workstation policy explicitly permits insecure guest logons.
        using var policy = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation");
        policy!.SetValue("AllowInsecureGuestAuth", 1, RegistryValueKind.DWord);
        using var parameters = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters");
        parameters!.SetValue("AllowInsecureGuestAuth", 1, RegistryValueKind.DWord);
    }
}
