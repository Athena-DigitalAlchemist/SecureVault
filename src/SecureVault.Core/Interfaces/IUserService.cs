using SecureVault.Core.Models;

namespace SecureVault.Core.Interfaces
{
    public interface IUserService
    {
        Task<User?> GetUserByIdAsync(int userId);
        Task<User?> GetUserByUsernameAsync(string username);
        Task<User?> GetUserByEmailAsync(string email);
        Task<bool> CreateUserAsync(User user);
        Task<bool> UpdateUserAsync(User user);
        Task<bool> DeleteUserAsync(int userId);
        Task<bool> ValidateUserCredentialsAsync(string username, string password);
        Task<bool> IsEmailConfirmedAsync(int userId);
        Task<bool> ConfirmEmailAsync(int userId, string token);
        Task<bool> UpdatePasswordAsync(int userId, string newPassword);
    }
}
