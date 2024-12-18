using System.Security.Cryptography;

namespace SecureVault.Core.Services
{
    public class PasswordGeneratorService
    {
        private const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
        private const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string NumberChars = "0123456789";
        private const string SpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

        public class PasswordOptions
        {
            public int Length { get; set; } = 16;
            public bool IncludeLowercase { get; set; } = true;
            public bool IncludeUppercase { get; set; } = true;
            public bool IncludeNumbers { get; set; } = true;
            public bool IncludeSpecial { get; set; } = true;
            public bool ExcludeSimilar { get; set; } = false;  // e.g., i, l, 1, L, o, 0, O
            public bool ExcludeAmbiguous { get; set; } = false; // e.g., {}[]()/<>
            public string CustomCharacters { get; set; } = "";
        }

        public string GeneratePassword(PasswordOptions options)
        {
            if (options.Length < 1)
                throw new ArgumentException("Password length must be at least 1 character.");

            var charGroups = new List<string>();
            var requiredChars = new List<char>();

            // Add character groups based on options
            if (options.IncludeLowercase)
            {
                var chars = options.ExcludeSimilar
                    ? LowercaseChars.Replace("i", "").Replace("l", "").Replace("o", "")
                    : LowercaseChars;
                charGroups.Add(chars);
                requiredChars.Add(GetRandomChar(chars));
            }

            if (options.IncludeUppercase)
            {
                var chars = options.ExcludeSimilar
                    ? UppercaseChars.Replace("I", "").Replace("L", "").Replace("O", "")
                    : UppercaseChars;
                charGroups.Add(chars);
                requiredChars.Add(GetRandomChar(chars));
            }

            if (options.IncludeNumbers)
            {
                var chars = options.ExcludeSimilar
                    ? NumberChars.Replace("0", "").Replace("1", "")
                    : NumberChars;
                charGroups.Add(chars);
                requiredChars.Add(GetRandomChar(chars));
            }

            if (options.IncludeSpecial)
            {
                var chars = options.ExcludeAmbiguous
                    ? SpecialChars.Replace("{", "").Replace("}", "").Replace("[", "").Replace("]", "")
                        .Replace("(", "").Replace(")", "").Replace("<", "").Replace(">", "")
                    : SpecialChars;
                charGroups.Add(chars);
                requiredChars.Add(GetRandomChar(chars));
            }

            if (!string.IsNullOrEmpty(options.CustomCharacters))
            {
                charGroups.Add(options.CustomCharacters);
                requiredChars.Add(GetRandomChar(options.CustomCharacters));
            }

            if (!charGroups.Any())
                throw new ArgumentException("At least one character group must be selected.");

            // Combine all allowed characters
            string allChars = string.Concat(charGroups);

            // Generate the password
            var password = new char[options.Length];

            // First, place required characters at random positions
            var positions = new HashSet<int>();
            foreach (char requiredChar in requiredChars)
            {
                int position;
                do
                {
                    position = GetRandomNumber(0, options.Length);
                } while (!positions.Add(position));

                password[position] = requiredChar;
            }

            // Fill remaining positions with random characters
            for (int i = 0; i < options.Length; i++)
            {
                if (!positions.Contains(i))
                {
                    password[i] = GetRandomChar(allChars);
                }
            }

            return new string(password);
        }

        public double CalculatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password))
                return 0;

            double strength = 0;

            // Length contribution (up to 40% of strength)
            double lengthScore = Math.Min(password.Length * 4, 40);
            strength += lengthScore;

            // Character set contribution (up to 40% of strength)
            if (password.Any(char.IsLower)) strength += 10;
            if (password.Any(char.IsUpper)) strength += 10;
            if (password.Any(char.IsDigit)) strength += 10;
            if (password.Any(c => !char.IsLetterOrDigit(c))) strength += 10;

            // Complexity contribution (up to 20% of strength)
            var uniqueChars = password.Distinct().Count();
            var uniqueCharScore = Math.Min((uniqueChars / (double)password.Length) * 20, 20);
            strength += uniqueCharScore;

            // Pattern detection (can reduce strength)
            if (HasRepeatingPatterns(password))
                strength *= 0.85;

            if (HasCommonSequences(password))
                strength *= 0.85;

            // Bonus for mixed character types in sequence
            bool hasMixedSequence = false;
            for (int i = 1; i < password.Length; i++)
            {
                if (char.IsLetter(password[i]) != char.IsLetter(password[i - 1]) ||
                    char.IsDigit(password[i]) != char.IsDigit(password[i - 1]) ||
                    (!char.IsLetterOrDigit(password[i]) != !char.IsLetterOrDigit(password[i - 1])))
                {
                    hasMixedSequence = true;
                    break;
                }
            }
            if (hasMixedSequence)
                strength *= 1.2;

            return Math.Min(strength, 100);
        }

        private bool HasRepeatingPatterns(string password)
        {
            // Check for repeating characters
            for (int i = 1; i < password.Length; i++)
            {
                if (password[i] == password[i - 1])
                    return true;
            }

            // Check for repeating patterns (length 2-4)
            for (int patternLength = 2; patternLength <= 4; patternLength++)
            {
                for (int i = 0; i < password.Length - patternLength * 2 + 1; i++)
                {
                    string pattern = password.Substring(i, patternLength);
                    string nextChars = password.Substring(i + patternLength, patternLength);
                    if (pattern == nextChars)
                        return true;
                }
            }

            return false;
        }

        private bool HasCommonSequences(string password)
        {
            string[] commonSequences = {
                "123", "234", "345", "456", "567", "678", "789",
                "abc", "bcd", "cde", "def", "efg", "fgh", "ghi",
                "hij", "ijk", "jkl", "klm", "lmn", "mno", "nop",
                "opq", "pqr", "qrs", "rst", "stu", "tuv", "uvw",
                "vwx", "wxy", "xyz"
            };

            string lowerPassword = password.ToLower();
            return commonSequences.Any(seq => lowerPassword.Contains(seq));
        }

        private char GetRandomChar(string chars)
        {
            return chars[GetRandomNumber(0, chars.Length)];
        }

        private int GetRandomNumber(int minValue, int maxValue)
        {
            var randomNumber = new byte[4];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                int value = BitConverter.ToInt32(randomNumber, 0);
                return Math.Abs(value % (maxValue - minValue)) + minValue;
            }
        }
    }
}
