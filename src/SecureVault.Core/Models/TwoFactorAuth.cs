namespace SecureVault.Core.Models
{
    public class TwoFactorAuthInfo
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string UserId { get; set; } = string.Empty;
        public string SecretKey { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
        public string? RecoveryEmail { get; set; }
        public string[] RecoveryCodes { get; set; } = Array.Empty<string>();
    }

    public class TwoFactorSetupInfo
    {
        public string SecretKey { get; set; } = string.Empty;
        public string QrCodeUri { get; set; } = string.Empty;
        public string ManualEntryKey { get; set; } = string.Empty;
        public string[] RecoveryCodes { get; set; } = Array.Empty<string>();
    }

    public class TwoFactorVerificationResult
    {
        public bool IsValid { get; set; }
        public string? Error { get; set; }
        public bool RequiresNewCode { get; set; }
        public DateTime? ValidUntil { get; set; }
    }
}
