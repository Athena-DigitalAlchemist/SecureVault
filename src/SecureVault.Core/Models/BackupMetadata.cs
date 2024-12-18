using System;

namespace SecureVault.Core.Models
{
    public class BackupMetadata
    {
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string EncryptedPath { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string Hash { get; set; } = string.Empty;
        public long Size { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastModified { get; set; }
        public string Description { get; set; } = string.Empty;
        public string Error { get; set; } = string.Empty;
        public string BackupPath { get; set; } = string.Empty;
        public bool IsAutomatic { get; set; }
        public bool IsEncrypted { get; set; }
        public DateTime? CompletedAt { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
    }
}
