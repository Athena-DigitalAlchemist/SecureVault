using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SecureVault.Core.Exceptions;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;

namespace SecureVault.Core.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly IUserService _userService;
        private readonly IHashingService _hashingService;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<AuthenticationService> _logger;
        private readonly string _jwtSecret;

        public AuthenticationService(
            IUserService userService,
            IHashingService hashingService,
            IAuditLogService auditLogService,
            ILogger<AuthenticationService> logger,
            string jwtSecret)
        {
            _userService = userService ?? throw new ArgumentNullException(nameof(userService));
            _hashingService = hashingService ?? throw new ArgumentNullException(nameof(hashingService));
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _jwtSecret = jwtSecret ?? throw new ArgumentNullException(nameof(jwtSecret));
        }

        public async Task<bool> ValidateCredentialsAsync(string username, string password)
        {
            try
            {
                var user = await _userService.GetUserByUsernameAsync(username);
                if (user == null)
                {
                    _logger.LogWarning($"Authentication failed: User not found: {username}");
                    return false;
                }

                var isValid = await _hashingService.VerifyPasswordAsync(password, user.PasswordHash, user.PasswordSalt);
                await _auditLogService.LogEventAsync(user.Id.ToString(), AuditEventType.PasswordValidated,
                    $"Authentication attempt: {(isValid ? "successful" : "failed")}");

                return isValid;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating credentials for user {username}");
                throw;
            }
        }

        public async Task<bool> CreateUserAsync(User user, string password)
        {
            try
            {
                var salt = await _hashingService.GenerateSaltAsync();
                var hash = await _hashingService.HashPasswordAsync(password, salt);

                user.PasswordHash = hash;
                user.PasswordSalt = salt;

                var success = await _userService.CreateUserAsync(user);
                if (success)
                {
                    await _auditLogService.LogEventAsync(user.Id.ToString(), AuditEventType.UserCreated, "User account created");
                }

                return success;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error creating user {user.Username}");
                throw;
            }
        }

        public async Task<bool> UpdateUserAsync(User user)
        {
            try
            {
                var success = await _userService.UpdateUserAsync(user);
                if (success)
                {
                    await _auditLogService.LogEventAsync(user.Id.ToString(), AuditEventType.UserUpdated, "User account updated");
                }
                return success;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating user {user.Id}");
                throw;
            }
        }

        public async Task<bool> DeleteUserAsync(string userId)
        {
            try
            {
                var success = await _userService.DeleteUserAsync(userId);
                if (success)
                {
                    await _auditLogService.LogEventAsync(userId, AuditEventType.UserDeleted, "User account deleted");
                }
                return success;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting user {userId}");
                throw;
            }
        }

        public async Task<bool> ChangePasswordAsync(string userId, string currentPassword, string newPassword)
        {
            try
            {
                var user = await _userService.GetUserByIdAsync(int.Parse(userId));
                if (user == null)
                {
                    _logger.LogWarning($"Password change failed: User not found: {userId}");
                    return false;
                }

                var isCurrentPasswordValid = await _hashingService.VerifyPasswordAsync(currentPassword, user.PasswordHash, user.PasswordSalt);
                if (!isCurrentPasswordValid)
                {
                    _logger.LogWarning($"Password change failed: Current password invalid for user {userId}");
                    return false;
                }

                var newSalt = await _hashingService.GenerateSaltAsync();
                var newHash = await _hashingService.HashPasswordAsync(newPassword, newSalt);

                user.PasswordHash = newHash;
                user.PasswordSalt = newSalt;
                await _userService.UpdateUserAsync(user);
                await _auditLogService.LogEventAsync(userId, AuditEventType.PasswordUpdated, "Password changed successfully");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error changing password for user {userId}");
                throw;
            }
        }

        public async Task<bool> ResetPasswordAsync(string userId, string resetToken, string newPassword)
        {
            try
            {
                var user = await _userService.GetUserByIdAsync(int.Parse(userId));
                if (user == null)
                {
                    _logger.LogWarning($"Password reset failed: User not found: {userId}");
                    return false;
                }

                // Validate reset token here...
                var newSalt = await _hashingService.GenerateSaltAsync();
                var newHash = await _hashingService.HashPasswordAsync(newPassword, newSalt);

                user.PasswordHash = newHash;
                user.PasswordSalt = newSalt;
                await _userService.UpdateUserAsync(user);
                await _auditLogService.LogEventAsync(userId, AuditEventType.PasswordUpdated, "Password reset successfully");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error resetting password for user {userId}");
                throw;
            }
        }

        public async Task<User?> GetUserAsync(string userId)
        {
            try
            {
                return await _userService.GetUserByIdAsync(int.Parse(userId));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting user {userId}");
                throw;
            }
        }

        public async Task<bool> ValidateTokenAsync(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_jwtSecret);

                try
                {
                    tokenHandler.ValidateToken(token, new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ClockSkew = TimeSpan.Zero
                    }, out SecurityToken validatedToken);

                    return true;
                }
                catch
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating token");
                throw;
            }
        }

        public async Task<string> GenerateTokenAsync(string userId)
        {
            try
            {
                var user = await _userService.GetUserByIdAsync(int.Parse(userId));
                if (user == null)
                {
                    throw new SecureVaultException($"User not found: {userId}");
                }

                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_jwtSecret);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.Name, userId),
                        new Claim(ClaimTypes.Email, user.Email),
                        new Claim(ClaimTypes.Role, user.Role)
                    }),
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha256Signature)
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                await _auditLogService.LogEventAsync(userId, AuditEventType.TokenGenerated, "JWT token generated");
                return tokenString;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error generating token for user {userId}");
                throw;
            }
        }

        public async Task<bool> RevokeTokenAsync(string token)
        {
            try
            {
                // In a production environment, you would typically:
                // 1. Add the token to a blacklist
                // 2. Store the blacklist in a fast-access store like Redis
                // 3. Check the blacklist in ValidateTokenAsync

                // For now, we'll just log the revocation
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_jwtSecret);

                var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var userId = principal.Identity?.Name;
                if (userId != null)
                {
                    await _auditLogService.LogEventAsync(userId, AuditEventType.TokenRevoked, "JWT token revoked");
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error revoking token");
                throw;
            }
        }
    }
}
