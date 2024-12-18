using System.Security.Cryptography;

namespace SecureVault.Core.Authentication
{
    public class MasterPasswordService
    {
        private const int SALT_SIZE = 32;
        private const int HASH_SIZE = 32;
        private const int ITERATIONS = 350000; // High iteration count for better security

        public class HashResult
        {
            public required string Salt { get; set; }
            public required string Hash { get; set; }
        }

        /// <summary>
        /// Creates a secure hash of the master password using PBKDF2 with a random salt
        /// </summary>
        public HashResult HashPassword(string masterPassword)
        {
            if (string.IsNullOrEmpty(masterPassword))
                throw new ArgumentException("Master password cannot be empty", nameof(masterPassword));

            // Generate a cryptographically secure random salt
            var salt = new byte[SALT_SIZE];
            RandomNumberGenerator.Fill(salt);

            // Generate the hash using PBKDF2
            var hash = GenerateHash(masterPassword, salt);

            return new HashResult
            {
                Salt = Convert.ToBase64String(salt),
                Hash = Convert.ToBase64String(hash)
            };
        }

        /// <summary>
        /// Verifies if the provided master password matches the stored hash
        /// </summary>
        public bool VerifyPassword(string masterPassword, HashResult storedHash)
        {
            if (string.IsNullOrEmpty(masterPassword))
                throw new ArgumentException("Master password cannot be empty", nameof(masterPassword));

            if (storedHash == null)
                throw new ArgumentNullException(nameof(storedHash));

            var salt = Convert.FromBase64String(storedHash.Salt);
            var hash = Convert.FromBase64String(storedHash.Hash);
            var computedHash = GenerateHash(masterPassword, salt);

            return CryptographicOperations.FixedTimeEquals(hash, computedHash);
        }

        private byte[] GenerateHash(string password, byte[] salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(
                password,
                salt,
                ITERATIONS,
                HashAlgorithmName.SHA512);

            return pbkdf2.GetBytes(HASH_SIZE);
        }

        /// <summary>
        /// Validates the strength of a master password
        /// </summary>
        public (bool IsValid, string ErrorMessage) ValidatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password))
                return (false, "Password cannot be empty.");

            if (password.Length < 12)
                return (false, "Password must be at least 12 characters long.");

            bool hasUpper = false;
            bool hasLower = false;
            bool hasDigit = false;
            bool hasSpecial = false;

            foreach (char c in password)
            {
                if (char.IsUpper(c)) hasUpper = true;
                else if (char.IsLower(c)) hasLower = true;
                else if (char.IsDigit(c)) hasDigit = true;
                else hasSpecial = true;
            }

            if (!hasUpper)
                return (false, "Password must contain at least one uppercase letter.");
            if (!hasLower)
                return (false, "Password must contain at least one lowercase letter.");
            if (!hasDigit)
                return (false, "Password must contain at least one digit.");
            if (!hasSpecial)
                return (false, "Password must contain at least one special character.");

            return (true, string.Empty);
        }
    }
}
