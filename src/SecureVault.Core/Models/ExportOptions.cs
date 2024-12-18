namespace SecureVault.Core.Models
{
    public class ExportOptions
    {
        public bool IncludePasswords { get; set; } = true;
        public bool IncludeNotes { get; set; } = true;
        public bool IncludeFiles { get; set; } = true;
        public bool IncludeAuditLogs { get; set; } = false;
        public bool IncludeSettings { get; set; } = false;
        public bool IncludeFileContents { get; set; } = true;
        public bool DecryptSensitiveData { get; set; } = false;
        public bool EncryptExport { get; set; } = true;
        public string? ExportPassword { get; set; }
        public string? ExportPath { get; set; }
        public string? ExportFormat { get; set; } = "json";
        public bool CompressExport { get; set; } = true;
    }
}