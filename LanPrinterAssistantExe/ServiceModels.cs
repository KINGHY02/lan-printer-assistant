namespace LanPrinterAssistant;

internal enum DiagnosticSeverity { Passed, Warning, Failed }

internal sealed record DiagnosticResult(
    string Title,
    DiagnosticSeverity Severity,
    string Detail,
    string? SuggestedAction = null);

internal sealed record OperationProgress(
    string Step,
    int Completed,
    int Total,
    bool CanCancel = true);
