using System;
using System.Linq;
using System.Security.Cryptography;

namespace SecureVault.Services
{
    public class PasswordGeneratorService
    {
        private const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
        private const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string NumberChars = "0123456789";
        private const string SpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

        public string GeneratePassword(
            int length = 16,
            bool useLowercase = true,
            bool useUppercase = true,
            bool useNumbers = true,
            bool useSpecialChars = true)
        {
            if (length < 1) throw new ArgumentException("Password length must be at least 1", nameof(length));
            if (!(useLowercase || useUppercase || useNumbers || useSpecialChars))
                throw new ArgumentException("At least one character set must be selected");

            var charSet = string.Empty;
            if (useLowercase) charSet += LowercaseChars;
            if (useUppercase) charSet += UppercaseChars;
            if (useNumbers) charSet += NumberChars;
            if (useSpecialChars) charSet += SpecialChars;

            var password = new char[length];
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] rngBytes = new byte[length];

                // Ensure at least one character from each selected set
                int position = 0;
                if (useLowercase && position < length)
                    password[position++] = LowercaseChars[GetSecureRandomNumber(rng, LowercaseChars.Length)];
                if (useUppercase && position < length)
                    password[position++] = UppercaseChars[GetSecureRandomNumber(rng, UppercaseChars.Length)];
                if (useNumbers && position < length)
                    password[position++] = NumberChars[GetSecureRandomNumber(rng, NumberChars.Length)];
                if (useSpecialChars && position < length)
                    password[position++] = SpecialChars[GetSecureRandomNumber(rng, SpecialChars.Length)];

                // Fill remaining positions
                for (int i = position; i < length; i++)
                {
                    password[i] = charSet[GetSecureRandomNumber(rng, charSet.Length)];
                }

                // Shuffle the password
                for (int i = length - 1; i > 0; i--)
                {
                    int j = GetSecureRandomNumber(rng, i + 1);
                    var temp = password[i];
                    password[i] = password[j];
                    password[j] = temp;
                }
            }

            return new string(password);
        }

        private int GetSecureRandomNumber(RNGCryptoServiceProvider rng, int max)
        {
            byte[] randomNumber = new byte[4];
            rng.GetBytes(randomNumber);
            return Math.Abs(BitConverter.ToInt32(randomNumber, 0)) % max;
        }
    }
}
