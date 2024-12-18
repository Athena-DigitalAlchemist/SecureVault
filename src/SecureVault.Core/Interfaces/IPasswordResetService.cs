namespace SecureVault.Core.Interfaces
{
    public interface IPasswordResetService
    {
        Task<string> GenerateResetTokenAsync(string userId);
        Task<bool> ValidateResetTokenAsync(string userId, string token);
        Task<bool> ResetPasswordAsync(string userId, string token, string newPassword);
        Task<bool> SendResetEmailAsync(string email);
        Task<bool> CancelResetRequestAsync(string userId);
        Task<bool> IsTokenExpiredAsync(string userId, string token);
        Task<bool> HasActiveResetRequestAsync(string userId);
    }
}
