using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;

namespace SecureVault.Core.Services
{
    public class HashingService : IHashingService
    {
        private readonly ILogger<HashingService> _logger;

        public HashingService(ILogger<HashingService> logger)
        {
            _logger = logger;
        }

        public async Task<string> HashPasswordAsync(string password, string salt)
        {
            try
            {
                using var pbkdf2 = new Rfc2898DeriveBytes(password, Convert.FromBase64String(salt), 10000, HashAlgorithmName.SHA512);
                var hash = pbkdf2.GetBytes(32);
                return Convert.ToBase64String(hash);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error hashing password");
                throw;
            }
        }

        public async Task<string> GenerateSaltAsync()
        {
            try
            {
                var salt = new byte[32];
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(salt);
                return Convert.ToBase64String(salt);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating salt");
                throw;
            }
        }

        public async Task<bool> VerifyPasswordAsync(string password, string hash, string salt)
        {
            try
            {
                var newHash = await HashPasswordAsync(password, salt);
                return newHash == hash;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying password");
                throw;
            }
        }

        public async Task<string> HashDataAsync(byte[] data)
        {
            try
            {
                using var sha512 = SHA512.Create();
                var hash = sha512.ComputeHash(data);
                return Convert.ToBase64String(hash);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error hashing data");
                throw;
            }
        }

        public async Task<string> HashFileAsync(string filePath)
        {
            try
            {
                using var sha512 = SHA512.Create();
                using var stream = File.OpenRead(filePath);
                var hash = await Task.Run(() => sha512.ComputeHash(stream));
                return Convert.ToBase64String(hash);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error hashing file");
                throw;
            }
        }
    }
}
