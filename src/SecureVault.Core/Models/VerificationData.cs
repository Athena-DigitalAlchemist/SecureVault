namespace SecureVault.Core.Models
{
    public class VerificationData
    {
        public required string UserId { get; set; }
        public required string Salt { get; set; }
        public required string PasswordHash { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastModified { get; set; }
        public required int IterationCount { get; set; }
        public required string KeyDerivationMethod { get; set; }
        public required string HashAlgorithm { get; set; }
        public string? RecoveryEmail { get; set; }
        public string? PhoneNumber { get; set; }
        public string? VerificationMethod { get; set; }
    }
}
