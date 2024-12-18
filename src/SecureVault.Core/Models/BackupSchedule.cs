namespace SecureVault.Core.Models
{
    public class BackupSchedule
    {
        public int IntervalInMinutes { get; set; }
        public string Description { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
        public DateTime? LastBackupTime { get; set; }
        public DateTime? NextBackupTime { get; set; }
    }
}
