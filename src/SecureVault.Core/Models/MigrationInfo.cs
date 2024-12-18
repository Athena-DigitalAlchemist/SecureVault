namespace SecureVault.Core.Models
{
    public class MigrationInfo
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Version { get; set; }
        public string Description { get; set; }
        public DateTime AppliedAt { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; }
        public TimeSpan Duration { get; set; }
        public string BackupPath { get; set; }
        public MigrationType Type { get; set; }
    }

    public enum MigrationType
    {
        Schema,
        Data,
        Rollback,
        Hotfix
    }
}
