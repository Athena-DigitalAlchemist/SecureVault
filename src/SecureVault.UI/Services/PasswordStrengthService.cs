using System;
using System.Linq;
using System.Text.RegularExpressions;
using SecureVault.Core.Models;

namespace SecureVault.Core.Services
{
    public interface IPasswordStrengthService
    {
        PasswordStrengthResult EvaluatePassword(string password);
        bool MeetsMinimumRequirements(string password);
    }

    public class PasswordStrengthService : IPasswordStrengthService
    {
        private readonly ISettingsService _settingsService;

        public PasswordStrengthService(ISettingsService settingsService)
        {
            _settingsService = settingsService;
        }

        public PasswordStrengthResult EvaluatePassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                return new PasswordStrengthResult { Score = 0 };
            }

            var result = new PasswordStrengthResult
            {
                HasUppercase = password.Any(char.IsUpper),
                HasLowercase = password.Any(char.IsLower),
                HasNumbers = password.Any(char.IsDigit),
                HasSpecialChars = password.Any(c => !char.IsLetterOrDigit(c))
            };

            // Calculate base score
            int score = 0;

            // Length score (up to 2 points)
            if (password.Length >= 8) score++;
            if (password.Length >= 12) score++;

            // Character variety score (up to 4 points)
            if (result.HasUppercase) score++;
            if (result.HasLowercase) score++;
            if (result.HasNumbers) score++;
            if (result.HasSpecialChars) score++;

            // Penalize for patterns
            if (HasRepeatingPatterns(password)) score--;
            if (HasSequentialPatterns(password)) score--;
            if (HasCommonPasswords(password)) score -= 2;

            // Ensure score is between 0 and 4
            result.Score = Math.Max(0, Math.Min(4, score));

            return result;
        }

        public bool MeetsMinimumRequirements(string password)
        {
            var settings = _settingsService.GetSettingsAsync().Result;
            var result = EvaluatePassword(password);

            return password.Length >= settings.MinPasswordLength &&
                   (!settings.RequireUppercase || result.HasUppercase) &&
                   (!settings.RequireLowercase || result.HasLowercase) &&
                   (!settings.RequireNumbers || result.HasNumbers) &&
                   (!settings.RequireSpecialChars || result.HasSpecialChars);
        }

        private bool HasRepeatingPatterns(string password)
        {
            // Check for repeating characters (e.g., "aaa")
            for (int i = 0; i < password.Length - 2; i++)
            {
                if (password[i] == password[i + 1] && password[i] == password[i + 2])
                {
                    return true;
                }
            }

            // Check for repeating patterns (e.g., "abcabc")
            for (int length = 2; length <= password.Length / 2; length++)
            {
                for (int i = 0; i <= password.Length - length * 2; i++)
                {
                    string pattern = password.Substring(i, length);
                    string nextChunk = password.Substring(i + length, length);
                    if (pattern == nextChunk)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private bool HasSequentialPatterns(string password)
        {
            const string sequences = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            
            for (int i = 0; i < password.Length - 2; i++)
            {
                string chunk = password.Substring(i, 3);
                if (sequences.Contains(chunk) || sequences.Contains(new string(chunk.Reverse().ToArray())))
                {
                    return true;
                }
            }

            return false;
        }

        private bool HasCommonPasswords(string password)
        {
            // This would typically check against a database of common passwords
            // For now, we'll just check some very common ones
            var commonPasswords = new[]
            {
                "password", "123456", "qwerty", "admin", "letmein",
                "welcome", "monkey", "password1", "abc123"
            };

            return commonPasswords.Contains(password.ToLower());
        }
    }
}
