using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Konscious.Security.Cryptography;
using SecureVault.Core.Interfaces;

namespace SecureVault.Core.Services
{
    public class PasswordHashingService : IPasswordHashingService
    {
        private const int SaltSize = 32;
        private const int HashSize = 32;
        private const int DegreeOfParallelism = 8;
        private const int Iterations = 4;
        private const int MemorySize = 1024 * 1024; // 1GB

        public async Task<string> HashPasswordAsync(string password, string salt)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));
            if (string.IsNullOrEmpty(salt))
                throw new ArgumentNullException(nameof(salt));

            var saltBytes = Convert.FromBase64String(salt);
            var passwordBytes = Encoding.UTF8.GetBytes(password);

            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = saltBytes,
                DegreeOfParallelism = DegreeOfParallelism,
                Iterations = Iterations,
                MemorySize = MemorySize
            };

            var hash = await Task.Run(() => argon2.GetBytes(HashSize));
            return Convert.ToBase64String(hash);
        }

        public async Task<string> GenerateSaltAsync()
        {
            var salt = new byte[SaltSize];
            RandomNumberGenerator.Fill(salt);
            return await Task.FromResult(Convert.ToBase64String(salt));
        }

        public async Task<bool> VerifyPasswordAsync(string password, string hashedPassword, string salt)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));
            if (string.IsNullOrEmpty(hashedPassword))
                throw new ArgumentNullException(nameof(hashedPassword));
            if (string.IsNullOrEmpty(salt))
                throw new ArgumentNullException(nameof(salt));

            var newHash = await HashPasswordAsync(password, salt);
            return hashedPassword.Equals(newHash, StringComparison.OrdinalIgnoreCase);
        }

        public async Task<bool> ValidatePasswordStrengthAsync(string password)
        {
            if (string.IsNullOrEmpty(password))
                return false;

            var result = await EstimatePasswordStrengthAsync(password);
            return result >= 80; // Minimum 80% strength required
        }

        public async Task<int> EstimatePasswordStrengthAsync(string password)
        {
            if (string.IsNullOrEmpty(password))
                return 0;

            int score = 0;

            // Length check
            if (password.Length >= 12) score += 25;
            else if (password.Length >= 8) score += 15;
            else if (password.Length >= 6) score += 10;

            // Complexity checks
            if (Regex.IsMatch(password, @"[A-Z]")) score += 15; // Uppercase
            if (Regex.IsMatch(password, @"[a-z]")) score += 15; // Lowercase
            if (Regex.IsMatch(password, @"[0-9]")) score += 15; // Numbers
            if (Regex.IsMatch(password, @"[^A-Za-z0-9]")) score += 15; // Special chars

            // Additional checks
            if (password.Length > 12) score += 10; // Extra length bonus
            if (Regex.IsMatch(password, @"[^A-Za-z0-9]{2,}")) score += 10; // Multiple special chars
            if (Regex.IsMatch(password, @"\d{2,}")) score += 10; // Multiple numbers

            // Penalty for common patterns
            if (Regex.IsMatch(password.ToLower(), @"(password|123|abc|qwerty)")) score -= 20;
            if (Regex.IsMatch(password, @"(.)\1{2,}")) score -= 15; // Repeated characters

            return await Task.FromResult(Math.Max(0, Math.Min(100, score)));
        }
    }
}