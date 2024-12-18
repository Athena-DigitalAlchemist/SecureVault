using System;

namespace SecureVault.Core.Models
{
    public class User
    {
        public string Id { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string PasswordSalt { get; set; } = string.Empty;
        public byte[] Salt { get; set; } = Array.Empty<byte>();
        public string Role { get; set; } = "User";
        public bool EmailConfirmed { get; set; }
        public string? EmailConfirmationToken { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastModified { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public bool IsActive { get; set; } = true;
        public bool IsTwoFactorEnabled { get; set; }
        public string? TwoFactorKey { get; set; }
        public string? RecoveryEmail { get; set; }
        public int FailedLoginAttempts { get; set; }
        public DateTime? LockoutEnd { get; set; }
    }
}
