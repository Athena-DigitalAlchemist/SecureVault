namespace SecureVault.Core.Models
{
    public class BackupCredential
    {
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public string BackupPath { get; set; } = string.Empty;
        public string EncryptedPassword { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime LastUsed { get; set; }
    }
}
