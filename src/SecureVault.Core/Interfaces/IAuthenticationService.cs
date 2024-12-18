using SecureVault.Core.Models;

namespace SecureVault.Core.Interfaces
{
    public interface IAuthenticationService
    {
        Task<bool> ValidateCredentialsAsync(string username, string password);
        Task<bool> CreateUserAsync(User user, string password);
        Task<bool> UpdateUserAsync(User user);
        Task<bool> DeleteUserAsync(string userId);
        Task<bool> ChangePasswordAsync(string userId, string currentPassword, string newPassword);
        Task<bool> ResetPasswordAsync(string userId, string resetToken, string newPassword);
        Task<User?> GetUserAsync(string userId);
        Task<bool> ValidateTokenAsync(string token);
        Task<string> GenerateTokenAsync(string userId);
        Task<bool> RevokeTokenAsync(string token);
    }
}
