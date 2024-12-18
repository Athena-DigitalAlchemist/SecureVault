namespace SecureVault.Core.Models
{
    public class UserProfile
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public required string Username { get; set; }
        public required string PasswordHash { get; set; }
        public required byte[] MasterKeySalt { get; set; }
        public string? Email { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastLoginAt { get; set; }
        public bool IsLocked { get; set; }
        public int FailedLoginAttempts { get; set; }
        public DateTime? LockoutEnd { get; set; }

        // Security settings
        public bool RequireMasterPasswordOnStartup { get; set; } = true;
        public bool UseWindowsHello { get; set; }
        public int AutoLockTimeoutMinutes { get; set; } = 5;
        public bool RequireMasterPasswordForSensitiveOperations { get; set; } = true;

        public UserProfile()
        {
            CreatedAt = DateTime.UtcNow;
            LastLoginAt = DateTime.UtcNow;
        }
    }
}