using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;

namespace SecureVault.Core.Services
{
    public class TwoFactorAuthService : ITwoFactorAuthService
    {
        private readonly IDatabaseService _databaseService;
        private readonly ILogger<TwoFactorAuthService> _logger;
        private const int RecoveryCodeCount = 8;
        private const int RecoveryCodeLength = 10;

        public TwoFactorAuthService(
            IDatabaseService databaseService,
            ILogger<TwoFactorAuthService> logger)
        {
            _databaseService = databaseService;
            _logger = logger;
        }

        public async Task<(string QrCodeUri, string ManualEntryKey)> GenerateSetupInfoAsync(string userId, string username)
        {
            try
            {
                var key = GenerateSecretKey();
                var uri = GenerateQrCodeUri(username, key);

                var user = await _databaseService.GetUserByIdAsync(userId);
                if (user == null)
                {
                    throw new InvalidOperationException("User not found");
                }

                user.TwoFactorKey = key;
                await _databaseService.UpdateUserAsync(user);

                return (uri, key);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate 2FA setup info for user {UserId}", userId);
                throw;
            }
        }

        public async Task<bool> ValidateCodeAsync(string userId, string code)
        {
            try
            {
                var user = await _databaseService.GetUserByIdAsync(userId);
                if (user == null || string.IsNullOrEmpty(user.TwoFactorKey))
                {
                    return false;
                }

                return ValidateTotp(user.TwoFactorKey, code);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate 2FA code for user {UserId}", userId);
                return false;
            }
        }

        public async Task<bool> EnableAsync(string userId, string code)
        {
            try
            {
                if (!await ValidateCodeAsync(userId, code))
                {
                    return false;
                }

                var user = await _databaseService.GetUserByIdAsync(userId);
                if (user == null)
                {
                    return false;
                }

                user.IsTwoFactorEnabled = true;
                return await _databaseService.UpdateUserAsync(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to enable 2FA for user {UserId}", userId);
                return false;
            }
        }

        public async Task<bool> DisableAsync(string userId, string code)
        {
            try
            {
                if (!await ValidateCodeAsync(userId, code))
                {
                    return false;
                }

                var user = await _databaseService.GetUserByIdAsync(userId);
                if (user == null)
                {
                    return false;
                }

                user.IsTwoFactorEnabled = false;
                user.TwoFactorKey = null;
                return await _databaseService.UpdateUserAsync(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to disable 2FA for user {UserId}", userId);
                return false;
            }
        }

        public async Task<bool> IsEnabledAsync(string userId)
        {
            try
            {
                var user = await _databaseService.GetUserByIdAsync(userId);
                return user?.IsTwoFactorEnabled ?? false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to check 2FA status for user {UserId}", userId);
                return false;
            }
        }

        public async Task<string[]> GenerateRecoveryCodesAsync(string userId)
        {
            try
            {
                var codes = new string[RecoveryCodeCount];
                for (int i = 0; i < RecoveryCodeCount; i++)
                {
                    codes[i] = GenerateRecoveryCode();
                }

                // Store hashed recovery codes in the database
                // Implementation needed

                return codes;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate recovery codes for user {UserId}", userId);
                throw;
            }
        }

        public async Task<bool> ValidateRecoveryCodeAsync(string userId, string code)
        {
            try
            {
                // Validate recovery code against stored hashed codes
                // Implementation needed
                throw new NotImplementedException();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate recovery code for user {UserId}", userId);
                return false;
            }
        }

        private string GenerateSecretKey()
        {
            var key = new byte[20];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(key);
            return Convert.ToBase64String(key);
        }

        private string GenerateQrCodeUri(string username, string secretKey)
        {
            var issuer = "SecureVault";
            var encodedIssuer = Uri.EscapeDataString(issuer);
            var encodedUsername = Uri.EscapeDataString(username);
            return $"otpauth://totp/{encodedIssuer}:{encodedUsername}?secret={secretKey}&issuer={encodedIssuer}";
        }

        private bool ValidateTotp(string secretKey, string code)
        {
            // TOTP validation implementation needed
            throw new NotImplementedException();
        }

        private string GenerateRecoveryCode()
        {
            var bytes = new byte[RecoveryCodeLength];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToHexString(bytes);
        }
    }
}
