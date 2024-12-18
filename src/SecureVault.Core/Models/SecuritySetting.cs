namespace SecureVault.Core.Models
{
    public class SecuritySetting
    {
        public int Id { get; set; }
        public string Key { get; set; }
        public string Value { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
    }
}
