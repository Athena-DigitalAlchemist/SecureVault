using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;

namespace SecureVault.Core.Services
{
    public class UserService : IUserService
    {
        private readonly IDatabaseService _databaseService;
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<UserService> _logger;

        public UserService(
            IDatabaseService databaseService,
            IEncryptionService encryptionService,
            ILogger<UserService> logger)
        {
            _databaseService = databaseService ?? throw new ArgumentNullException(nameof(databaseService));
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<User?> GetUserByIdAsync(int userId)
        {
            try
            {
                return await _databaseService.GetUserByIdAsync(userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user {UserId}", userId);
                throw;
            }
        }

        public async Task<User?> GetUserByUsernameAsync(string username)
        {
            try
            {
                return await _databaseService.GetUserByUsernameAsync(username);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user by username {Username}", username);
                throw;
            }
        }

        public async Task<User?> GetUserByEmailAsync(string email)
        {
            try
            {
                return await _databaseService.GetUserByEmailAsync(email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user by email {Email}", email);
                throw;
            }
        }

        public async Task<bool> CreateUserAsync(User user)
        {
            try
            {
                var salt = _encryptionService.GenerateSalt();
                var passwordHash = await _encryptionService.HashPasswordAsync(user.Password, salt);
                user.PasswordHash = passwordHash;
                user.Salt = Convert.ToBase64String(salt);
                return await _databaseService.CreateUserAsync(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating user {Username}", user.Username);
                throw;
            }
        }

        public async Task<bool> UpdateUserAsync(User user)
        {
            try
            {
                return await _databaseService.UpdateUserAsync(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user {UserId}", user.Id);
                throw;
            }
        }

        public async Task<bool> DeleteUserAsync(int userId)
        {
            try
            {
                return await _databaseService.DeleteUserAsync(userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user {UserId}", userId);
                throw;
            }
        }

        public async Task<bool> ValidateUserCredentialsAsync(string username, string password)
        {
            try
            {
                var user = await GetUserByUsernameAsync(username);
                if (user == null || string.IsNullOrEmpty(user.Salt))
                {
                    return false;
                }

                var passwordHash = await _encryptionService.HashPasswordAsync(password, Convert.FromBase64String(user.Salt));
                return user.PasswordHash == passwordHash;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating credentials for user {Username}", username);
                throw;
            }
        }

        public async Task<bool> IsEmailConfirmedAsync(int userId)
        {
            try
            {
                var user = await GetUserByIdAsync(userId);
                return user?.EmailConfirmed ?? false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking email confirmation for user {UserId}", userId);
                throw;
            }
        }

        public async Task<bool> ConfirmEmailAsync(int userId, string token)
        {
            try
            {
                var user = await GetUserByIdAsync(userId);
                if (user == null || user.EmailConfirmationToken != token)
                {
                    return false;
                }

                user.EmailConfirmed = true;
                user.EmailConfirmationToken = null;
                return await UpdateUserAsync(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error confirming email for user {UserId}", userId);
                throw;
            }
        }

        public async Task<bool> UpdatePasswordAsync(int userId, string newPassword)
        {
            try
            {
                var user = await GetUserByIdAsync(userId);
                if (user == null)
                {
                    return false;
                }

                var salt = _encryptionService.GenerateSalt();
                var passwordHash = await _encryptionService.HashPasswordAsync(newPassword, salt);
                user.PasswordHash = passwordHash;
                user.Salt = Convert.ToBase64String(salt);
                return await UpdateUserAsync(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating password for user {UserId}", userId);
                throw;
            }
        }
    }
}
