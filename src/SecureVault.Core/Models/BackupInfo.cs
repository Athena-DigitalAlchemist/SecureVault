using System;

namespace SecureVault.Core.Models
{
    public class BackupInfo
    {
        public int Id { get; set; }
        public string FileName { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public long Size { get; set; }
        public bool IsAutomatic { get; set; }
        public BackupStatus Status { get; set; }
        public string Description { get; set; } = string.Empty;
    }

    public enum BackupStatus
    {
        InProgress,
        Completed,
        Failed,
        Cancelled
    }
}
