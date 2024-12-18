namespace SecureVault.Core.Models
{
    public class BackupInfoViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public string CreatedBy { get; set; } = string.Empty;
        public long SizeInBytes { get; set; }
        public bool IsVerified { get; set; }
        public string Status { get; set; } = string.Empty;
        public BackupConfiguration? AutoBackupConfig { get; set; }
    }

    public class BackupStatistics
    {
        public int TotalBackups { get; set; }
        public long TotalSizeBytes { get; set; }
        public DateTime? LastBackupTime { get; set; }
        public DateTime? NextScheduledBackup { get; set; }
        public int SuccessfulVerifications { get; set; }
        public int FailedVerifications { get; set; }
    }
}
