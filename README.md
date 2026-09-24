# 局域网打印机连接助手

面向 Windows 10/11 x64 的局域网打印机发现、共享和连接工具。

## 功能

- 自动识别本机局域网网段；
- 检测共享电脑和共享打印机；
- 连接 Windows 共享打印机；
- 共享本机打印机并配置局域网打印权限；
- 支持扫描进度、取消扫描、连接诊断和测试页；
- 默认处理常见的共享打印机 RPC 兼容问题（包括 0x0000011B）；
- 关于窗口支持手动检查 GitHub 最新版本；
- 自包含单文件 EXE，不需要额外安装 .NET 或 PowerShell。

## 下载

请在 GitHub 的 **Releases** 页面下载最新版本的 `局域网打印机连接助手.exe`。

软件需要管理员权限，用于配置 Windows 打印服务、打印 RPC、共享权限和防火墙规则。共享模式默认启用 Guest、Everyone 打印权限和 RPC 兼容设置，以降低普通用户配置失败的概率；这些设置会降低局域网安全性，仅建议在可信办公网络中使用。关闭 Guest 时不会回滚 Everyone 或 RPC 兼容设置。

## 构建

需要 .NET 8 SDK 和 Windows x64 环境：

```powershell
dotnet publish .\LanPrinterAssistantExe\LanPrinterAssistant.csproj -c Release -r win-x64 --self-contained true -o .\原生发布 /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
```

## 隐私与安全

程序不上传电脑名、IP、打印机名或扫描结果，也不访问互联网服务。Guest 免密访问会降低局域网安全性，应按公司网络策略使用。

## 版权与使用限制

© 2026 KiNG 版权所有。创作者：KiNG，QQ：3148213528。

未经创作者书面许可，不得复制、修改、反编译、拆分、转售、转发或重新发布本软件及其衍生版本。商业使用、定制开发、批量授权或转载申请，请联系创作者。
