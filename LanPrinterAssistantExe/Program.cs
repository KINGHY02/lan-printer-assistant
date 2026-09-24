using System.Diagnostics;
using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace LanPrinterAssistant;

internal sealed class ScanResult
{
    public string Ip = "";
    public bool Ping;
    public bool Smb;
    public bool Raw;
    public bool Ipp;
    public string Shares = "";
}

static class NativePrinter
{
    const uint PRINTER_ENUM_LOCAL = 2, PRINTER_ENUM_CONNECTIONS = 4, PRINTER_ATTRIBUTE_SHARED = 8;
    const uint STYPE_PRINTQ = 1, MAX_PREFERRED_LENGTH = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct PRINTER_INFO_2
    {
        public IntPtr pServerName, pPrinterName, pShareName, pPortName, pDriverName, pComment, pLocation, pDevMode, pSepFile, pPrintProcessor, pDatatype, pParameters, pSecurityDescriptor;
        public uint Attributes, Priority, DefaultPriority, StartTime, UntilTime, Status, cJobs, AveragePPM;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct SHARE_INFO_1 { public IntPtr shi1_netname; public uint shi1_type; public IntPtr shi1_remark; }
    [DllImport("winspool.drv", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool EnumPrinters(uint flags, string? name, uint level, IntPtr buffer, uint size, out uint needed, out uint returned);
    [DllImport("winspool.drv", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool OpenPrinter(string name, out IntPtr handle, IntPtr defaults);
    [DllImport("winspool.drv", SetLastError = true)] static extern bool ClosePrinter(IntPtr handle);
    [DllImport("winspool.drv", SetLastError = true)] static extern bool GetPrinter(IntPtr handle, uint level, IntPtr buffer, uint size, out uint needed);
    [DllImport("winspool.drv", SetLastError = true)] static extern bool SetPrinter(IntPtr handle, uint level, IntPtr info, uint command);
    [StructLayout(LayoutKind.Sequential)] struct PRINTER_INFO_3 { public IntPtr pSecurityDescriptor; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string stringSecurityDescriptor, uint stringSDRevision, out IntPtr securityDescriptor, out uint securityDescriptorSize);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr LocalFree(IntPtr hMem);
    [DllImport("winspool.drv", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool AddPrinterConnection(string name);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] static extern int NetShareEnum(string server, int level, out IntPtr buffer, uint prefmaxlen, out uint entriesread, out uint totalentries, ref uint resume);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] static extern int NetWkstaGetInfo(string? servername, int level, out IntPtr buffer);
    [DllImport("netapi32.dll")] static extern int NetApiBufferFree(IntPtr buffer);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr OpenService(IntPtr manager, string service, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool StartService(IntPtr service, int args, IntPtr argv);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool ControlService(IntPtr service, uint control, ref SERVICE_STATUS status);
    [StructLayout(LayoutKind.Sequential)] struct SERVICE_STATUS { public uint type, state, controls, win32, service, checkpoint, hint; }
    [StructLayout(LayoutKind.Sequential)] struct WKSTA_INFO_100 { public uint platformId; public IntPtr computerName, langroup; public ushort verMajor, verMinor; }

    public static List<string> LocalPrinters()
    {
        var result = new List<string>(); uint needed, count;
        // Sharing is only supported for printers installed on this computer.
        // Do not include existing UNC connections such as \\server\printer.
        EnumPrinters(PRINTER_ENUM_LOCAL, null, 2, IntPtr.Zero, 0, out needed, out count);
        if (needed == 0) return result; var buffer = Marshal.AllocHGlobal((int)needed);
        try { if (!EnumPrinters(PRINTER_ENUM_LOCAL, null, 2, buffer, needed, out needed, out count)) return result; var size = Marshal.SizeOf<PRINTER_INFO_2>(); for (var i = 0; i < count; i++) { var p = Marshal.PtrToStructure<PRINTER_INFO_2>(buffer + i * size); if (p.pPrinterName != IntPtr.Zero) result.Add(Marshal.PtrToStringUni(p.pPrinterName)!); } } finally { Marshal.FreeHGlobal(buffer); } return result;
    }
    public static string PrintShares(string address)
    {
        var result = new List<string>(); uint resume = 0, entries, total; IntPtr buffer; var server = address.StartsWith("\\\\") ? address : "\\\\" + address; var code = NetShareEnum(server, 1, out buffer, MAX_PREFERRED_LENGTH, out entries, out total, ref resume); if (code != 0 || buffer == IntPtr.Zero) return "";
        try { var size = Marshal.SizeOf<SHARE_INFO_1>(); for (var i = 0; i < entries; i++) { var share = Marshal.PtrToStructure<SHARE_INFO_1>(buffer + i * size); if (share.shi1_type == STYPE_PRINTQ && share.shi1_netname != IntPtr.Zero) result.Add(Marshal.PtrToStringUni(share.shi1_netname)!); } } finally { NetApiBufferFree(buffer); } return string.Join("; ", result.Distinct());
    }
    public static string RemoteComputerName(string address)
    {
        var server = address.StartsWith("\\\\") ? address : "\\\\" + address;
        var code = NetWkstaGetInfo(server, 100, out var buffer);
        if (code != 0 || buffer == IntPtr.Zero) return "";
        try
        {
            var info = Marshal.PtrToStructure<WKSTA_INFO_100>(buffer);
            return info.computerName == IntPtr.Zero ? "" : (Marshal.PtrToStringUni(info.computerName) ?? "").Trim();
        }
        finally { NetApiBufferFree(buffer); }
    }
    public static bool Share(string printer, string shareName)
    {
        if (!OpenPrinter(printer, out var handle, IntPtr.Zero)) return false; uint needed;
        try { GetPrinter(handle, 2, IntPtr.Zero, 0, out needed); var source = Marshal.AllocHGlobal((int)needed); try { if (!GetPrinter(handle, 2, source, needed, out needed)) return false; var info = Marshal.PtrToStructure<PRINTER_INFO_2>(source); var sharePtr = Marshal.StringToHGlobalUni(shareName); try { info.pShareName = sharePtr; info.Attributes |= PRINTER_ATTRIBUTE_SHARED; var target = Marshal.AllocHGlobal(Marshal.SizeOf<PRINTER_INFO_2>()); try { Marshal.StructureToPtr(info, target, false); return SetPrinter(handle, 2, target, 0); } finally { Marshal.FreeHGlobal(target); } } finally { Marshal.FreeHGlobal(sharePtr); } } finally { Marshal.FreeHGlobal(source); } } finally { ClosePrinter(handle); }
    }
    public static bool Unshare(string printer)
    {
        if (!OpenPrinter(printer, out var handle, IntPtr.Zero)) return false; uint needed;
        try { GetPrinter(handle, 2, IntPtr.Zero, 0, out needed); var source = Marshal.AllocHGlobal((int)needed); try { if (!GetPrinter(handle, 2, source, needed, out needed)) return false; var info = Marshal.PtrToStructure<PRINTER_INFO_2>(source); info.pShareName = IntPtr.Zero; info.Attributes &= ~PRINTER_ATTRIBUTE_SHARED; var target = Marshal.AllocHGlobal(Marshal.SizeOf<PRINTER_INFO_2>()); try { Marshal.StructureToPtr(info, target, false); return SetPrinter(handle, 2, target, 0); } finally { Marshal.FreeHGlobal(target); } } finally { Marshal.FreeHGlobal(source); } } finally { ClosePrinter(handle); }
    }
    public static bool GrantEveryonePrintPermission(string printer)
    {
        // Printer access right for Everyone: use, manage documents, and read
        // the queue. This is the permission most client PCs need for a shared
        // office printer, while administration remains restricted.
        const string sddl = "D:(A;;LCSWSDRCWDWO;;;WD)";
        if (!OpenPrinter(printer, out var handle, IntPtr.Zero)) return false;
        IntPtr descriptor = IntPtr.Zero;
        try
        {
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out descriptor, out _)) return false;
            var info = new PRINTER_INFO_3 { pSecurityDescriptor = descriptor };
            var target = Marshal.AllocHGlobal(Marshal.SizeOf<PRINTER_INFO_3>());
            try { Marshal.StructureToPtr(info, target, false); return SetPrinter(handle, 3, target, 0); }
            finally { Marshal.FreeHGlobal(target); }
        }
        finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); ClosePrinter(handle); }
    }
    public static bool AddConnection(string unc) => AddPrinterConnection(unc);
    public static bool Exists(string name) => OpenPrinter(name, out var handle, IntPtr.Zero) && ClosePrinter(handle);
    public static void RestartSpooler()
    {
        var manager = OpenSCManager(null, null, 0xF003F); if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error()); var service = OpenService(manager, "Spooler", 0xF01FF); if (service == IntPtr.Zero) { CloseServiceHandle(manager); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        try { var status = new SERVICE_STATUS(); ControlService(service, 1, ref status); Thread.Sleep(700); if (!StartService(service, 0, IntPtr.Zero) && Marshal.GetLastWin32Error() != 1056) throw new Win32Exception(Marshal.GetLastWin32Error()); } finally { CloseServiceHandle(service); CloseServiceHandle(manager); }
    }
    public static string[] LocalIpv4() => NetworkInfo.AllLanAddresses().Select(x => x.Address.ToString()).Distinct().ToArray();
    public static void EnableFirewall()
    {
        // Windows localizes the built-in firewall group name.
        RunHidden("netsh.exe", "advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=Yes");
        RunHidden("netsh.exe", "advfirewall firewall set rule group=\"文件和打印机共享\" new enable=Yes");
    }
    public static void EnableGuest() { using var workstation = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"); workstation!.SetValue("AllowInsecureGuestAuth", 1, RegistryValueKind.DWord); using var server = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"); server!.SetValue("RestrictNullSessAccess", 0, RegistryValueKind.DWord); }
    public static (int? Workstation, int? Server) ReadGuestSettings()
    {
        using var workstation = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters");
        using var server = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
        return (workstation?.GetValue("AllowInsecureGuestAuth") as int?, server?.GetValue("RestrictNullSessAccess") as int?);
    }
    public static void RestoreGuestSettings((int? Workstation, int? Server) original)
    {
        using var workstation = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters");
        using var server = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
        if (original.Workstation.HasValue) workstation!.SetValue("AllowInsecureGuestAuth", original.Workstation.Value, RegistryValueKind.DWord); else workstation!.DeleteValue("AllowInsecureGuestAuth", false);
        if (original.Server.HasValue) server!.SetValue("RestrictNullSessAccess", original.Server.Value, RegistryValueKind.DWord); else server!.DeleteValue("RestrictNullSessAccess", false);
    }
    static void RunHidden(string file, string args) { using var p = Process.Start(new ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden }); p?.WaitForExit(); }
}

internal sealed record LanAddress(IPAddress Address, IPAddress Mask, bool HasGateway, string InterfaceName)
{
    public int PrefixLength => Mask.GetAddressBytes().Sum(byteCount => System.Numerics.BitOperations.PopCount((uint)byteCount));
    public uint NetworkValue => ToUInt(Address) & ToUInt(Mask);
    public uint BroadcastValue => NetworkValue | ~ToUInt(Mask);
    public string Prefix
    {
        get
        {
            var address = Address.GetAddressBytes();
            var mask = Mask.GetAddressBytes();
            var network = address.Zip(mask, (a, m) => (byte)(a & m)).ToArray();
            // The scanner edits only the last octet, so expose a /24 prefix.
            // For a wider or narrower subnet this is still the correct local /24
            // portion and the log explains the detected mask.
            return $"{network[0]}.{network[1]}.{network[2]}.";
        }
    }
    public IEnumerable<string> UsableAddresses(int maxCount = 4096)
    {
        var first = NetworkValue + 1; var last = BroadcastValue > 0 ? BroadcastValue - 1 : 0;
        var count = last >= first ? (ulong)last - first + 1 : 0;
        if (count > (ulong)maxCount) throw new InvalidOperationException($"检测到 /{PrefixLength} 网段，共有 {count} 个地址。请在“范围”中缩小扫描范围后再试。");
        for (var value = first; value <= last; value++) yield return FromUInt(value).ToString();
    }
    static uint ToUInt(IPAddress address) { var b = address.GetAddressBytes(); return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3]; }
    static IPAddress FromUInt(uint value) => new(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });
}

internal static class NetworkInfo
{
    public static IReadOnlyList<LanAddress> AllLanAddresses()
    {
        var result = new List<LanAddress>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback || nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
            try
            {
                var props = nic.GetIPProperties();
                var hasGateway = props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(g.Address));
                foreach (var item in props.UnicastAddresses.Where(x => x.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(x.Address)))
                {
                    var bytes = item.Address.GetAddressBytes();
                    var isPrivate = bytes[0] == 10 || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || (bytes[0] == 192 && bytes[1] == 168);
                    if (isPrivate) result.Add(new LanAddress(item.Address, item.IPv4Mask, hasGateway, nic.Name));
                }
            }
            catch { }
        }
        return result.OrderByDescending(x => x.HasGateway).ThenBy(x => x.InterfaceName).ToArray();
    }

    public static LanAddress? Primary() => AllLanAddresses().FirstOrDefault();
}

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}

internal sealed class MainForm : Form
{
    readonly TextBox host = Box("");
    readonly TextBox share = Box("");
    readonly TextBox ip = Box("");
    readonly TextBox prefix = Box("");
    readonly TextBox start = Box("1");
    readonly TextBox end = Box("254");
    readonly DataGridView grid = new();
    readonly TextBox log = new();
    readonly Label status = new();
    readonly Button check = new() { Text = "检测指定 IP" };
    readonly Button scan = new() { Text = "查找共享打印机" };
    readonly Button connect = new() { Text = "连接选中打印机" };
    readonly Button clear = new() { Text = "清空结果" };
    readonly Button shareOwner = new() { Text = "共享我的打印机" };
    readonly Button testPage = new() { Text = "打印测试页" };
    readonly NetworkService networkService = new();
    readonly PrinterService printerService = new();
    readonly WindowsRepairService repairService = new();
    int selectionVersion;
    CancellationTokenSource? scanCts;

    static TextBox Box(string text) => new() { Text = text };

    public MainForm()
    {
        Text = "局域网打印机连接助手";
        StartPosition = FormStartPosition.CenterScreen;
        try { using var executableIcon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); if (executableIcon != null) Icon = (Icon)executableIcon.Clone(); } catch { }
        ClientSize = new Size(940, 720);
        MinimumSize = new Size(940, 620);
        Font = new Font("Microsoft YaHei UI", 10);
        BackColor = Color.FromArgb(246, 248, 251);
        AddLabel("共享电脑：", 25, 82); Place(host, 145, 78, 220);
        AddLabel("打印机名称：", 390, 82); Place(share, 510, 78, 220);
        AddLabel("共享电脑 IP：", 25, 122); Place(ip, 145, 118, 160);
        AddLabel("局域网范围：", 330, 122); Place(prefix, 420, 118, 120);
        AddLabel("范围", 555, 122); Place(start, 600, 118, 40); Place(end, 650, 118, 45);
        SetDetectedNetwork(false);
        PlaceButton(check, 25, 160, 130); PlaceButton(scan, 170, 160, 130); PlaceButton(connect, 315, 160, 160); connect.BackColor = Color.FromArgb(190, 228, 248); PlaceButton(clear, 490, 160, 110); PlaceButton(shareOwner, 615, 160, 150); shareOwner.BackColor = Color.FromArgb(186, 239, 194); PlaceButton(testPage, 780, 160, 125); testPage.Enabled = false;
        foreach (var button in new[] { check, scan, connect, clear, shareOwner, testPage }) { button.FlatStyle = FlatStyle.Flat; button.FlatAppearance.BorderColor = Color.FromArgb(180, 190, 200); button.Cursor = Cursors.Hand; }
        status.Text = "状态：等待操作"; status.ForeColor = Color.FromArgb(30, 79, 120); status.BackColor = Color.FromArgb(226, 237, 248); status.AutoSize = false; status.Size = new Size(880, 28); status.Location = new Point(25, 205); status.AutoEllipsis = false; status.TextAlign = ContentAlignment.MiddleLeft; status.Padding = new Padding(10, 0, 10, 0); Controls.Add(status);
        grid.Location = new Point(25, 240); grid.Size = new Size(880, 295); grid.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right; grid.ReadOnly = true; grid.AllowUserToAddRows = false; grid.RowHeadersVisible = false; grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect; grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill; grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing; grid.ColumnHeadersHeight = 32; grid.ColumnHeadersDefaultCellStyle.WrapMode = DataGridViewTriState.False; grid.BorderStyle = BorderStyle.FixedSingle; grid.BackgroundColor = Color.White; grid.GridColor = Color.FromArgb(220, 226, 232); grid.EnableHeadersVisualStyles = false; grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(231, 237, 244); grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(35, 48, 62); grid.ColumnHeadersDefaultCellStyle.Font = new Font(Font, FontStyle.Bold); grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(24, 126, 186); grid.DefaultCellStyle.SelectionForeColor = Color.White; grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(248, 250, 252); grid.RowTemplate.Height = 28;
        foreach (var c in new[] { ("IP", "IP 地址"), ("Ping", "在线状态"), ("Smb", "共享电脑"), ("Raw", "打印服务"), ("Ipp", "网络打印"), ("Shares", "已确认打印机") }) grid.Columns.Add(c.Item1, c.Item2);
        Controls.Add(grid);
        log.Location = new Point(25, 550); log.Size = new Size(880, 115); log.Multiline = true; log.ReadOnly = true; log.ScrollBars = ScrollBars.None; log.BackColor = Color.White; log.BorderStyle = BorderStyle.FixedSingle; log.Font = new Font("Consolas", 9.5f); log.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right; Controls.Add(log);
        var hint = AddLabel("选择一台已确认的共享打印机后，点击“连接选中打印机”。程序会自动检查并修复本机设置。", 25, 680); hint.Anchor = AnchorStyles.Bottom | AnchorStyles.Left; hint.ForeColor = Color.FromArgb(90, 105, 120);
        var header = new Panel { Dock = DockStyle.Top, Height = 58, BackColor = Color.FromArgb(27, 84, 126) };
        var logo = new PictureBox { Location = new Point(18, 8), Size = new Size(42, 42), SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.Transparent };
        try { using var appIcon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); if (appIcon != null) logo.Image = appIcon.ToBitmap(); } catch { }
        var title = new Label { Text = "局域网打印机连接助手", ForeColor = Color.White, Font = new Font("Microsoft YaHei UI", 14, FontStyle.Bold), AutoSize = true, Location = new Point(70, 9) };
        var subtitle = new Label { Text = "发现、连接和共享局域网打印机", ForeColor = Color.FromArgb(205, 229, 245), Font = new Font("Microsoft YaHei UI", 9), AutoSize = true, Location = new Point(72, 35) };
        var about = new Button { Text = "关于", Size = new Size(76, 30), Location = new Point(838, 14), Anchor = AnchorStyles.Top | AnchorStyles.Right, FlatStyle = FlatStyle.Flat, ForeColor = Color.White, BackColor = Color.FromArgb(39, 103, 148), Cursor = Cursors.Hand, TabStop = false };
        about.FlatAppearance.BorderColor = Color.FromArgb(145, 195, 225); about.FlatAppearance.MouseOverBackColor = Color.FromArgb(49, 121, 166); about.BringToFront();
        header.Controls.Add(logo); header.Controls.Add(title); header.Controls.Add(subtitle); Controls.Add(header);
        // Keep the About entry on the form's top z-order so it remains visible
        // above the docked title panel on all Windows 10/11 themes.
        Controls.Add(about); about.BringToFront();
        Resize += (_, _) => LayoutResponsive(hint);
        LayoutResponsive(hint);
        check.Click += async (_, _) => await CheckOne(); scan.Click += async (_, _) => await StartOrCancelScan(); connect.Click += async (_, _) => await ConnectPrinter(); shareOwner.Click += (_, _) => ShowShareDialog(); testPage.Click += async (_, _) => await PrintTestPageAsync(); clear.Click += (_, _) => { grid.Rows.Clear(); log.Clear(); status.Text = "状态：等待操作"; }; about.Click += (_, _) => ShowAboutDialog();
        grid.SelectionChanged += async (_, _) => await SelectRowAsync();
        WriteLog("程序已启动。已根据本机活动网卡自动填写局域网前缀；没有保存任何地址。");
    }

    void ShowAboutDialog()
    {
        using var dialog = new Form
        {
            Text = "关于局域网打印机连接助手",
            StartPosition = FormStartPosition.CenterParent,
            ClientSize = new Size(520, 500),
            MinimumSize = new Size(520, 500),
            MaximizeBox = false,
            MinimizeBox = false,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            Font = Font,
            BackColor = Color.FromArgb(246, 248, 251)
        };
        try { using var appIcon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); if (appIcon != null) dialog.Icon = (Icon)appIcon.Clone(); } catch { }
        var banner = new Panel { Location = new Point(0, 0), Size = new Size(520, 78), BackColor = Color.FromArgb(27, 84, 126) };
        var icon = new PictureBox { Location = new Point(22, 17), Size = new Size(44, 44), SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.Transparent };
        try { using var appIcon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); if (appIcon != null) icon.Image = appIcon.ToBitmap(); } catch { }
        banner.Controls.Add(icon);
        banner.Controls.Add(new Label { Text = "局域网打印机连接助手", ForeColor = Color.White, Font = new Font("Microsoft YaHei UI", 15, FontStyle.Bold), AutoSize = true, Location = new Point(80, 13) });
        banner.Controls.Add(new Label { Text = "发现、连接和共享局域网打印机", ForeColor = Color.FromArgb(205, 229, 245), AutoSize = true, Location = new Point(82, 43) });
        var version = typeof(MainForm).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
        var text = new Label { AutoSize = false, Location = new Point(28, 98), Size = new Size(464, 350), ForeColor = Color.FromArgb(45, 55, 65), Text = $"版本：{version}\r\n\r\n功能：\r\n• 检测本机局域网和共享打印机\r\n• 连接 Windows 共享打印机\r\n• 共享本机打印机并配置局域网权限\r\n• 提供连接前检查、自动修复和测试页\r\n\r\n隐私：程序只检测用户指定的局域网地址，不上传电脑名、IP 或打印机信息。\r\n\r\n© 2026 KiNG 版权所有\r\n创作者：KiNG    QQ：3148213528\r\n未经创作者书面许可，不得复制、修改、反编译、拆分、转售、转发或重新发布本软件及其衍生版本。\r\n商业使用、定制开发、批量授权或转载申请，请联系创作者。" };
        var checkUpdate = new Button { Text = "检查更新", Location = new Point(295, 452), Size = new Size(105, 34) };
        var close = new Button { Text = "确定", DialogResult = DialogResult.OK, Location = new Point(410, 452), Size = new Size(82, 34) };
        checkUpdate.Click += async (_, _) => await CheckForUpdatesAsync(dialog, checkUpdate, version);
        dialog.Controls.Add(banner); dialog.Controls.Add(text); dialog.Controls.Add(checkUpdate); dialog.Controls.Add(close); dialog.AcceptButton = close; dialog.ShowDialog(this);
    }

    static async Task CheckForUpdatesAsync(Form owner, Button button, string currentVersion)
    {
        const string apiUrl = "https://api.github.com/repos/KINGHY02/lan-printer-assistant/releases/latest";
        const string releasePage = "https://github.com/KINGHY02/lan-printer-assistant/releases/latest";
        button.Enabled = false; var originalText = button.Text; button.Text = "检查中…";
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("LanPrinterAssistant/1.0");
            using var response = await client.GetAsync(apiUrl);
            response.EnsureSuccessStatusCode();
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var tag = document.RootElement.GetProperty("tag_name").GetString()?.Trim() ?? "";
            var normalized = tag.TrimStart('v', 'V');
            if (!Version.TryParse(normalized, out var latest) || !Version.TryParse(currentVersion, out var current))
                throw new InvalidOperationException("GitHub 返回的版本号格式无法识别。");
            if (latest <= current)
            {
                MessageBox.Show(owner, $"当前已经是最新版本（v{current}）。", "检查更新", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            var choice = MessageBox.Show(owner, $"发现新版本 v{latest}。\r\n是否打开 GitHub 下载页面？", "发现新版本", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
            if (choice == DialogResult.Yes) Process.Start(new ProcessStartInfo(releasePage) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(owner, "检查更新失败。请检查网络连接，或稍后直接访问 GitHub Releases。\r\n\r\n" + ex.Message, "检查更新", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally { button.Enabled = true; button.Text = originalText; }
    }

    Label AddLabel(string text, int x, int y) { var l = new Label { Text = text, AutoSize = true, Location = new Point(x, y), ForeColor = Color.FromArgb(45, 55, 65) }; Controls.Add(l); return l; }
    void Place(Control c, int x, int y, int w) { c.Location = new Point(x, y); c.Size = new Size(w, 27); Controls.Add(c); }
    void PlaceButton(Button b, int x, int y, int w) { b.Location = new Point(x, y); b.Size = new Size(w, 38); Controls.Add(b); }
    void WriteLog(string text) { log.AppendText($"{DateTime.Now:HH:mm:ss}  {text}{Environment.NewLine}"); log.SelectionStart = log.TextLength; log.ScrollToCaret(); }
    void LayoutResponsive(Label hint)
    {
        var width = Math.Max(300, ClientSize.Width - 50);
        status.Width = width;
        grid.Width = width;
        log.Width = width;
        log.Top = Math.Max(360, ClientSize.Height - 170);
        hint.Top = ClientSize.Height - 40;
        grid.Height = Math.Max(120, log.Top - grid.Top - 15);
    }
    void SetDetectedNetwork(bool writeLog)
    {
        var lan = NetworkInfo.Primary();
        if (lan == null)
        {
            if (writeLog) WriteLog("未检测到活动的局域网 IPv4 网卡，请确认已连接 Wi-Fi 或网线。");
            return;
        }
        prefix.Text = lan.Prefix;
        if (writeLog) WriteLog($"已检测本机局域网：{lan.Address}，掩码 {lan.Mask}，网段前缀 {lan.Prefix}，IPv4 前缀长度 /{lan.PrefixLength}");
    }
    void Busy(bool value) { check.Enabled = !value; scan.Enabled = !value || scanCts != null; connect.Enabled = !value; shareOwner.Enabled = !value; testPage.Enabled = !value && !string.IsNullOrWhiteSpace(host.Text) && !string.IsNullOrWhiteSpace(share.Text); clear.Enabled = !value; Cursor = value ? Cursors.WaitCursor : Cursors.Default; }

    async Task<bool> Tcp(string address, int port, CancellationToken token = default) => await networkService.TestPortAsync(address, port, token);
    async Task<bool> PingHost(string address, CancellationToken token = default) => await networkService.PingAsync(address, token);
    async Task<string> Shares(string address, CancellationToken token = default) => await networkService.GetPrinterSharesAsync(address, token);
    async Task<ScanResult> Inspect(string address, CancellationToken token = default) => await networkService.InspectAsync(address, token);
    void AddRow(ScanResult r) { grid.Rows.Add(r.Ip, r.Ping ? "在线" : "未响应/禁用", !string.IsNullOrWhiteSpace(r.Shares) ? "已确认共享" : (r.Smb ? "端口响应" : "无响应"), r.Raw ? "端口响应" : "无响应", r.Ipp ? "端口响应" : "无响应", string.IsNullOrWhiteSpace(r.Shares) ? "" : r.Shares); }

    async Task CheckOne()
    {
        try { Busy(true); grid.Rows.Clear(); var address = ip.Text.Trim(); if (!IPAddress.TryParse(address, out _)) throw new Exception("请输入正确的 IP 地址。"); status.Text = $"状态：正在检测 {address}"; WriteLog($"开始检测 {address}"); var r = await Inspect(address); AddRow(r); WriteLog($"{address}：共享={r.Smb}，9100={r.Raw}，631={r.Ipp}，共享打印机={r.Shares}"); status.Text = "状态：检测完成"; } catch (Exception ex) { WriteLog("错误：" + ex.Message); status.Text = "状态：检测失败"; } finally { Busy(false); }
    }
    async Task StartOrCancelScan()
    {
        if (scanCts != null) { scanCts.Cancel(); return; }
        await ScanSubnet();
    }
    async Task ScanSubnet()
    {
        scanCts = new CancellationTokenSource();
        var currentScan = scanCts;
        scan.Text = "取消扫描"; scan.BackColor = Color.FromArgb(255, 210, 210);
        try
        {
            Busy(true); grid.Rows.Clear(); SetDetectedNetwork(true);
            if (!Regex.IsMatch(prefix.Text.Trim(), @"^\d{1,3}(\.\d{1,3}){2}\.$")) throw new Exception("局域网范围格式不正确，例如 192.168.1.");
            if (!int.TryParse(start.Text, out var a) || !int.TryParse(end.Text, out var b) || a < 1 || b > 254 || a > b) throw new Exception("范围必须在 1 到 254 之间。");
            var lan = NetworkInfo.Primary();
            var autoRange = lan != null && prefix.Text.Trim() == lan.Prefix && a == 1 && b == 254;
            var addresses = autoRange && lan != null && lan.PrefixLength != 24
                ? lan.UsableAddresses().ToArray()
                : Enumerable.Range(a, b - a + 1).Select(n => prefix.Text.Trim() + n).ToArray();
            WriteLog($"开始扫描 {addresses.Length} 个地址（最多同时检测 12 个地址）");
            var slots = new SemaphoreSlim(12); var completed = 0;
            async Task<ScanResult> LimitedInspect(string address) { await slots.WaitAsync(currentScan.Token); try { return await Inspect(address, currentScan.Token); } finally { slots.Release(); } }
            var pending = addresses.Select(LimitedInspect).ToList();
            while (pending.Count > 0)
            {
                var finished = await Task.WhenAny(pending); pending.Remove(finished); var result = await finished; var done = Interlocked.Increment(ref completed);
                if (result.Ping || result.Smb || result.Raw || result.Ipp) { AddRow(result); if (result.Smb || result.Raw || result.Ipp) WriteLog($"{result.Ip}：共享={result.Smb}，9100={result.Raw}，631={result.Ipp}，共享打印机={result.Shares}"); }
                status.Text = $"状态：扫描中 {done}/{addresses.Length}";
            }
            slots.Dispose(); status.Text = $"状态：扫描完成，发现 {grid.Rows.Count} 个响应地址";
        }
        catch (OperationCanceledException) { status.Text = $"状态：扫描已取消，保留 {grid.Rows.Count} 个结果"; WriteLog("用户取消扫描。"); }
        catch (Exception ex) { WriteLog("错误：" + ex.Message); status.Text = "状态：扫描失败"; }
        finally { currentScan.Dispose(); if (ReferenceEquals(scanCts, currentScan)) scanCts = null; scan.Text = "查找共享打印机"; scan.BackColor = SystemColors.Control; Busy(false); }
    }
    async Task SelectRowAsync()
    {
        var version = ++selectionVersion;
        if (grid.SelectedRows.Count == 0) return;
        var row = grid.SelectedRows[0];
        var address = row.Cells["IP"].Value?.ToString() ?? "";
        var names = row.Cells["Shares"].Value?.ToString() ?? "";
        var selectedShare = string.IsNullOrWhiteSpace(names) ? "" : names.Split(';')[0].Trim();

        // Update the controls immediately. Network name lookup must never block the UI thread.
        ip.Text = address;
        host.Text = address;
        if (!string.IsNullOrWhiteSpace(selectedShare)) share.Text = selectedShare;
        testPage.Enabled = !string.IsNullOrWhiteSpace(host.Text) && !string.IsNullOrWhiteSpace(share.Text);
        WriteLog($"已选择 {address}；正在读取电脑名；共享打印机={share.Text}");

        string computer;
        try
        {
            computer = await Task.Run(() =>
            {
                var result = NativePrinter.RemoteComputerName(address);
                if (!string.IsNullOrWhiteSpace(result)) return result;
                try { return Dns.GetHostEntry(address).HostName; } catch { return ""; }
            }).WaitAsync(TimeSpan.FromSeconds(1.5));
        }
        catch (TimeoutException) { computer = ""; }
        catch { computer = ""; }

        if (version != selectionVersion || IsDisposed) return;
        if (!string.IsNullOrWhiteSpace(computer)) host.Text = computer;
        testPage.Enabled = !string.IsNullOrWhiteSpace(host.Text) && !string.IsNullOrWhiteSpace(share.Text);
        WriteLog($"已选择 {address}；电脑名={host.Text}；共享打印机={share.Text}");
    }

    async Task ConnectPrinter()
    {
        try
        {
            Busy(true); status.ForeColor = Color.FromArgb(30, 79, 120);
            var machine = host.Text.Trim(); var printer = share.Text.Trim(); var address = ip.Text.Trim();
            if (string.IsNullOrWhiteSpace(machine) || string.IsNullOrWhiteSpace(printer)) throw new Exception("共享电脑名称和打印机共享名不能为空。");
            if (!IPAddress.TryParse(address, out _) && !string.IsNullOrWhiteSpace(address))
            {
                var resolved = Dns.GetHostAddresses(address).FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
                if (resolved != null) address = resolved.ToString();
            }
            if (!IPAddress.TryParse(address, out _)) throw new Exception("请输入共享电脑的 IPv4 地址，或先从扫描结果中选择设备。");
            status.Text = "状态：正在检查共享连接"; WriteLog($"连接前检查：{address}、445 端口、共享名 {printer}");
            if (!await Tcp(address, 445)) throw new Exception($"无法访问 {address} 的 445 端口。请检查网络隔离、防火墙或共享电脑是否开机。");
            var remoteName = await Task.Run(() => NativePrinter.RemoteComputerName(address)).WaitAsync(TimeSpan.FromSeconds(2.5));
            var remoteShares = await Task.Run(() => NativePrinter.PrintShares(address)).WaitAsync(TimeSpan.FromSeconds(2.5));
            if (string.IsNullOrWhiteSpace(remoteShares) || !remoteShares.Split(';').Any(x => string.Equals(x.Trim(), printer, StringComparison.OrdinalIgnoreCase)))
                throw new Exception($"{address} 的 445 端口有响应，但没有发现共享打印机“{printer}”。请确认共享名和共享权限。");
            if (!string.IsNullOrWhiteSpace(remoteName)) { machine = remoteName; host.Text = remoteName; }
            ip.Text = address; WriteLog($"连接前检查通过：电脑名={machine}，共享打印机={printer}");
            status.Text = "状态：正在配置并连接打印机"; WriteLog($"正在连接 \\\\{machine}\\{printer}");
            await Task.Run(() => ConfigureAndInstall(machine, printer)); status.Text = "状态：连接成功"; status.ForeColor = Color.Green; WriteLog("连接成功，驱动和端口已验证。"); MessageBox.Show("共享打印机连接成功。", "完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (TimeoutException) { status.Text = "状态：连接失败"; status.ForeColor = Color.Red; var message = "共享电脑响应超时。请确认电脑未休眠，并检查网络隔离或防火墙设置。"; WriteLog("连接失败：" + message); MessageBox.Show(message, "连接失败", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        catch (Exception ex) { status.Text = "状态：连接失败"; status.ForeColor = Color.Red; WriteLog("连接失败：" + ex.Message); MessageBox.Show(ex.Message, "连接失败", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        finally { Busy(false); }
    }
    async Task PrintTestPageAsync()
    {
        try
        {
            Busy(true); var machine = host.Text.Trim(); var printer = share.Text.Trim(); if (string.IsNullOrWhiteSpace(machine) || string.IsNullOrWhiteSpace(printer)) throw new Exception("请先选择并连接共享打印机。");
            var unc = $"\\\\{machine}\\{printer}"; if (!printerService.Exists(unc)) throw new Exception("本机没有找到已连接的打印机，请先完成连接。");
            status.Text = "状态：正在提交测试页"; WriteLog($"正在提交测试页：{unc}");
            using var process = Process.Start(new ProcessStartInfo("rundll32.exe", $"printui.dll,PrintUIEntry /k /n \"{unc}\"") { UseShellExecute = false, CreateNoWindow = true });
            if (process == null) throw new Exception("无法启动 Windows 打印测试页组件。");
            await Task.Run(() => process.WaitForExit(5000));
            if (process.HasExited && process.ExitCode != 0) throw new Exception($"Windows 打印组件返回错误代码 {process.ExitCode}。");
            status.Text = "状态：测试页已提交"; WriteLog("测试页已提交到打印队列，请查看打印机输出或 Windows 打印队列。");
        }
        catch (Exception ex) { status.Text = "状态：测试页失败"; WriteLog("测试页失败：" + ex.Message); MessageBox.Show(ex.Message, "测试页失败", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        finally { Busy(false); }
    }
    static string SuggestShareName(string printerName)
    {
        var value = printerName.Trim();
        if (value.StartsWith("\\\\", StringComparison.Ordinal))
            value = value[(value.LastIndexOf('\\') + 1)..];
        value = Regex.Replace(value, "[\\\\/:*?\"<>|]", "_").Trim().TrimEnd('.');
        return string.IsNullOrWhiteSpace(value) ? "共享打印机" : value[..Math.Min(value.Length, 80)];
    }
    void ShowShareDialog()
    {
        using var dialog = new Form { Text = "共享者设置", StartPosition = FormStartPosition.CenterParent, ClientSize = new Size(560, 470), Font = Font };
        var originalGuest = NativePrinter.ReadGuestSettings();
        var list = new ComboBox { Location = new Point(25, 55), Size = new Size(490, 28), DropDownStyle = ComboBoxStyle.DropDownList };
        var name = new TextBox { Location = new Point(25, 125), Size = new Size(490, 28) };
        var guest = new CheckBox { Text = "允许 Guest 免密访问（会降低局域网安全性）", Location = new Point(25, 165), AutoSize = true, Checked = true };
        var everyone = new CheckBox { Text = "允许局域网用户打印（添加 Everyone 打印权限）", Location = new Point(25, 190), AutoSize = true, Checked = true };
        var info = new TextBox { Location = new Point(25, 225), Size = new Size(490, 120), Multiline = true, ReadOnly = true, BackColor = Color.White, ScrollBars = ScrollBars.Vertical };
        var enable = new Button { Text = "启用共享", Location = new Point(25, 370), Size = new Size(130, 38) };
        var unshare = new Button { Text = "取消共享", Location = new Point(170, 370), Size = new Size(130, 38) };
        var restoreGuest = new Button { Text = "关闭 Guest", Location = new Point(315, 370), Size = new Size(130, 38) };
        var close = new Button { Text = "关闭", Location = new Point(465, 370), Size = new Size(70, 38) };
        dialog.Controls.Add(new Label { Text = "选择本机打印机：", Location = new Point(25, 25), AutoSize = true }); dialog.Controls.Add(list); dialog.Controls.Add(new Label { Text = "共享名：", Location = new Point(25, 95), AutoSize = true }); dialog.Controls.Add(name); dialog.Controls.Add(guest); dialog.Controls.Add(everyone); dialog.Controls.Add(info); dialog.Controls.Add(enable); dialog.Controls.Add(unshare); dialog.Controls.Add(restoreGuest); dialog.Controls.Add(close);
        foreach (var printer in printerService.GetLocalPrinters()) list.Items.Add(printer);
        if (list.Items.Count > 0) { list.SelectedIndex = 0; name.Text = SuggestShareName(list.SelectedItem!.ToString()!); }
        info.ForeColor = Color.DarkOrange; info.Text = "程序默认开启共享所需的兼容设置：Guest、Everyone 打印权限和 0x0000011B RPC 兼容项。\r\nGuest 和 RPC 兼容设置会降低局域网安全性，仅建议在可信办公网络使用。\r\n如公司环境支持 Windows 账户认证，建议关闭 Guest。";
        list.SelectedIndexChanged += (_, _) => { if (list.SelectedItem != null) name.Text = SuggestShareName(list.SelectedItem.ToString()!); };
        enable.Click += (_, _) =>
        {
            try
            {
                if (list.SelectedItem == null || string.IsNullOrWhiteSpace(name.Text)) throw new Exception("请选择打印机并填写共享名。");
                var selected = list.SelectedItem.ToString()!; var shareName = name.Text.Trim();
                if (!printerService.Share(selected, shareName)) throw new Win32Exception(Marshal.GetLastWin32Error(), "启用打印机共享失败。");
                if (everyone.Checked && !printerService.GrantEveryonePrintPermission(selected)) throw new Win32Exception(Marshal.GetLastWin32Error(), "共享已建立，但写入 Everyone 打印权限失败。");
                repairService.EnablePrinterSharingFirewall(); repairService.ConfigurePrintRpc(); repairService.RestartPrintSpooler(); if (guest.Checked) repairService.EnableGuestAccess();
                var addresses = NativePrinter.LocalIpv4(); var computer = Environment.MachineName;
                info.ForeColor = Color.DarkGreen; info.Text = "共享已启用。\r\n电脑名：" + computer + "\r\nIP 地址：" + string.Join(", ", addresses) + "\r\n共享路径：\\\\" + computer + "\\" + shareName + "\r\n\r\n请保持本电脑和打印机开机。";
            }
            catch (Exception ex) { info.ForeColor = Color.Red; info.Text = "启用失败：\r\n" + ex.Message; }
        };
        unshare.Click += (_, _) => { try { if (list.SelectedItem == null) throw new Exception("请选择打印机。"); if (!printerService.Unshare(list.SelectedItem.ToString()!)) throw new Win32Exception(Marshal.GetLastWin32Error(), "取消共享失败。"); info.ForeColor = Color.DarkGreen; info.Text = "已取消该打印机共享。"; } catch (Exception ex) { info.ForeColor = Color.Red; info.Text = "取消共享失败：\r\n" + ex.Message; } };
        restoreGuest.Click += (_, _) => { try { repairService.RestoreGuestAccess(originalGuest); info.ForeColor = Color.DarkGreen; info.Text = "已关闭 Guest 免密访问。\r\nEveryone 打印权限和 RPC 兼容设置保持不变，已连接的电脑仍可继续打印。\r\n后续新连接将需要 Windows 账户权限或公司网络允许的认证方式。"; } catch (Exception ex) { info.ForeColor = Color.Red; info.Text = "关闭 Guest 失败：\r\n" + ex.Message; } };
        close.Click += (_, _) => dialog.Close(); dialog.ShowDialog(this);
    }
    void ConfigureAndInstall(string machine, string printer)
    {
        repairService.ConfigureGuestClient();
        repairService.ConfigurePrintRpc();
        repairService.RestartPrintSpooler();
        var unc = $"\\\\{machine}\\{printer}";
        if (!printerService.Exists(unc) && !printerService.AddConnectionWithWindowsFallback(unc, out var errorCode))
        {
            var codeText = $"{errorCode} (0x{errorCode:X8})";
            var systemMessage = errorCode == 0 ? "Windows 未返回具体错误码。" : new Win32Exception(errorCode).Message;
            throw new Exception($"Windows 无法安装共享打印机。错误代码：{codeText}。\r\n系统提示：{systemMessage}\r\n\r\n请检查共享主机是否提供兼容驱动，或公司策略是否禁止自动安装共享打印机驱动。");
        }
        if (!printerService.Exists(unc)) throw new Exception("连接命令完成，但系统没有找到该打印机。");
    }
}
