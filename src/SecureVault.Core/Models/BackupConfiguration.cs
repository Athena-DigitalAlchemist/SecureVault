namespace SecureVault.Core.Models
{
    public class BackupConfiguration
    {
        public string BackupPath { get; set; } = string.Empty;
        public bool AutoBackupEnabled { get; set; }
        public int BackupFrequencyDays { get; set; }
        public int RetentionPeriodDays { get; set; }
        public bool EncryptBackups { get; set; }
        public int MaxBackupCount { get; set; }
        public long MaxBackupSize { get; set; }
        public string BackupFormat { get; set; } = string.Empty;
        public bool CompressBackups { get; set; }
        public DateTime? LastBackupTime { get; set; }
        
        // Compatibility properties
        public bool IsEnabled => AutoBackupEnabled;
        public DateTime? LastBackup => LastBackupTime;
        public int Interval => BackupFrequencyDays;
        public string Id => BackupPath;
    }
}
