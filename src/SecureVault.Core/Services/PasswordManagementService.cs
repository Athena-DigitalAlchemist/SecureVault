using System.Security.Cryptography;
using System.Text;
using SecureVault.Core.Interfaces;

namespace SecureVault.Core.Services
{
    public class PasswordManagementService : IPasswordManagementService
    {
        private readonly IAuditLogService _auditLogService;

        public PasswordManagementService(IAuditLogService auditLogService)
        {
            _auditLogService = auditLogService;
        }

        public async Task<string> GenerateSecurePasswordAsync(int length = 16, bool includeSpecialChars = true,
            bool includeNumbers = true, bool includeUppercase = true)
        {
            const string lowerChars = "abcdefghijklmnopqrstuvwxyz";
            const string upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string numbers = "0123456789";
            const string specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

            var allowedChars = new StringBuilder(lowerChars);
            if (includeUppercase) allowedChars.Append(upperChars);
            if (includeNumbers) allowedChars.Append(numbers);
            if (includeSpecialChars) allowedChars.Append(specialChars);

            var password = new StringBuilder();
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[length];

            rng.GetBytes(bytes);
            for (int i = 0; i < length; i++)
            {
                password.Append(allowedChars[bytes[i] % allowedChars.Length]);
            }

            await _auditLogService.LogEventAsync("System", AuditEventType.PasswordGenerated, "Password generated successfully");
            return password.ToString();
        }

        public async Task<(int score, string[] weaknesses)> ValidatePasswordStrengthAsync(string password)
        {
            var weaknesses = new List<string>();
            var score = 100;

            if (string.IsNullOrEmpty(password))
            {
                return (0, new[] { "Password cannot be empty" });
            }

            // Length check
            if (password.Length < 8)
            {
                score -= 20;
                weaknesses.Add("Password is too short (minimum 8 characters)");
            }
            else if (password.Length > 20)
            {
                score += 10;
            }

            // Complexity checks
            if (!password.Any(char.IsUpper))
            {
                score -= 10;
                weaknesses.Add("Missing uppercase letters");
            }
            if (!password.Any(char.IsLower))
            {
                score -= 10;
                weaknesses.Add("Missing lowercase letters");
            }
            if (!password.Any(char.IsDigit))
            {
                score -= 10;
                weaknesses.Add("Missing numbers");
            }
            if (!password.Any(c => !char.IsLetterOrDigit(c)))
            {
                score -= 10;
                weaknesses.Add("Missing special characters");
            }

            // Pattern checks
            if (HasRepeatingCharacters(password))
            {
                score -= 10;
                weaknesses.Add("Contains repeating characters");
            }

            score = Math.Max(0, Math.Min(100, score));
            await _auditLogService.LogEventAsync("System", AuditEventType.PasswordValidated, $"Password strength score: {score}");
            return (score, weaknesses.ToArray());
        }

        public async Task<bool> IsPasswordCompromisedAsync(string password)
        {
            // In a real implementation, this would check against known password breach databases
            // For now, we'll implement a basic check for common passwords
            var commonPasswords = new HashSet<string>
            {
                "password", "123456", "qwerty", "admin", "letmein",
                "welcome", "monkey", "password1", "abc123"
            };

            var isCompromised = commonPasswords.Contains(password.ToLower());
            await _auditLogService.LogEventAsync("System", AuditEventType.PasswordChecked,
                $"Password compromise check completed: {(isCompromised ? "Compromised" : "Safe")}");

            return isCompromised;
        }

        public async Task<string> EstimatePasswordStrengthAsync(string password)
        {
            var (score, _) = await ValidatePasswordStrengthAsync(password);
            var combinations = CalculatePossibleCombinations(password);

            // Assume 10 billion guesses per second for a modern system
            const double guessesPerSecond = 10000000000;
            var secondsToCrack = combinations / guessesPerSecond;

            if (secondsToCrack < 60) return "Less than a minute";
            if (secondsToCrack < 3600) return $"{Math.Round(secondsToCrack / 60)} minutes";
            if (secondsToCrack < 86400) return $"{Math.Round(secondsToCrack / 3600)} hours";
            if (secondsToCrack < 31536000) return $"{Math.Round(secondsToCrack / 86400)} days";
            return $"{Math.Round(secondsToCrack / 31536000)} years";
        }

        private bool HasRepeatingCharacters(string password)
        {
            for (int i = 0; i < password.Length - 2; i++)
            {
                if (password[i] == password[i + 1] && password[i] == password[i + 2])
                    return true;
            }
            return false;
        }

        private double CalculatePossibleCombinations(string password)
        {
            int charset = 26; // lowercase letters
            if (password.Any(char.IsUpper)) charset += 26;
            if (password.Any(char.IsDigit)) charset += 10;
            if (password.Any(c => !char.IsLetterOrDigit(c))) charset += 32;

            return Math.Pow(charset, password.Length);
        }
    }
}
