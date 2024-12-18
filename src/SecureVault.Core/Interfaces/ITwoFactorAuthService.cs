namespace SecureVault.Core.Interfaces
{
    public interface ITwoFactorAuthService
    {
        Task<(string QrCodeUri, string ManualEntryKey)> GenerateSetupInfoAsync(string userId, string username);
        Task<bool> ValidateCodeAsync(string userId, string code);
        Task<bool> EnableAsync(string userId, string code);
        Task<bool> DisableAsync(string userId, string code);
        Task<bool> IsEnabledAsync(string userId);
        Task<string[]> GenerateRecoveryCodesAsync(string userId);
        Task<bool> ValidateRecoveryCodeAsync(string userId, string code);
    }
}
