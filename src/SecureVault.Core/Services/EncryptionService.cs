using System.Security.Cryptography;
using System.Text;
using SecureVault.Core.Interfaces;

namespace SecureVault.Core.Services
{
    public class EncryptionService : IEncryptionService
    {
        private const int KeySize = 32; // 256 bits
        private const int SaltSize = 16; // 128 bits
        private const int Iterations = 100000;

        public string Encrypt(string plainText, string key)
        {
            using var aes = Aes.Create();
            aes.Key = Convert.FromBase64String(key);
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            var result = new byte[aes.IV.Length + cipherBytes.Length];
            Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
            Buffer.BlockCopy(cipherBytes, 0, result, aes.IV.Length, cipherBytes.Length);

            return Convert.ToBase64String(result);
        }

        public string Decrypt(string cipherText, string key)
        {
            var fullCipher = Convert.FromBase64String(cipherText);
            
            using var aes = Aes.Create();
            aes.Key = Convert.FromBase64String(key);

            var iv = new byte[aes.BlockSize / 8];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, cipher.Length);

            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            var plainBytes = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
            return Encoding.UTF8.GetString(plainBytes);
        }

        public string ReEncrypt(string cipherText, string oldKey, string newKey)
        {
            var plainText = Decrypt(cipherText, oldKey);
            return Encrypt(plainText, newKey);
        }

        public string GenerateSalt()
        {
            var salt = new byte[SaltSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);
            return Convert.ToBase64String(salt);
        }

        public string HashPassword(string password, string salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(
                password,
                Convert.FromBase64String(salt),
                Iterations,
                HashAlgorithmName.SHA256);

            var hash = pbkdf2.GetBytes(KeySize);
            return Convert.ToBase64String(hash);
        }

        public bool VerifyPassword(string password, string hash, string salt)
        {
            var newHash = HashPassword(password, salt);
            return newHash == hash;
        }

        public string GenerateKey()
        {
            var key = new byte[KeySize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(key);
            return Convert.ToBase64String(key);
        }

        public string DeriveKey(string password, string salt, int iterations = 100000)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(
                password,
                Convert.FromBase64String(salt),
                iterations,
                HashAlgorithmName.SHA256);

            var key = pbkdf2.GetBytes(KeySize);
            return Convert.ToBase64String(key);
        }

        public bool ValidateKey(string key)
        {
            try
            {
                var keyBytes = Convert.FromBase64String(key);
                return keyBytes.Length == KeySize;
            }
            catch
            {
                return false;
            }
        }

        public string EncryptFile(string filePath, string key)
        {
            var fileBytes = File.ReadAllBytes(filePath);
            var encryptedBytes = EncryptBytes(fileBytes, key);
            var encryptedPath = filePath + ".encrypted";
            File.WriteAllBytes(encryptedPath, encryptedBytes);
            return encryptedPath;
        }

        public string DecryptFile(string filePath, string key)
        {
            var encryptedBytes = File.ReadAllBytes(filePath);
            var decryptedBytes = DecryptBytes(encryptedBytes, key);
            var decryptedPath = filePath.Replace(".encrypted", ".decrypted");
            File.WriteAllBytes(decryptedPath, decryptedBytes);
            return decryptedPath;
        }

        public string GenerateHash(string input)
        {
            using var sha256 = SHA256.Create();
            var inputBytes = Encoding.UTF8.GetBytes(input);
            var hashBytes = sha256.ComputeHash(inputBytes);
            return Convert.ToBase64String(hashBytes);
        }

        public string GenerateRandomPassword(int length = 16, bool useSpecialChars = true)
        {
            const string lowerChars = "abcdefghijklmnopqrstuvwxyz";
            const string upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string numbers = "0123456789";
            const string specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

            var chars = lowerChars + upperChars + numbers;
            if (useSpecialChars) chars += specialChars;

            var password = new char[length];
            using var rng = RandomNumberGenerator.Create();

            for (int i = 0; i < length; i++)
            {
                var randomBytes = new byte[4];
                rng.GetBytes(randomBytes);
                var randomInt = BitConverter.ToInt32(randomBytes, 0);
                password[i] = chars[Math.Abs(randomInt % chars.Length)];
            }

            return new string(password);
        }

        private byte[] EncryptBytes(byte[] plainBytes, string key)
        {
            using var aes = Aes.Create();
            aes.Key = Convert.FromBase64String(key);
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            var result = new byte[aes.IV.Length + cipherBytes.Length];
            Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
            Buffer.BlockCopy(cipherBytes, 0, result, aes.IV.Length, cipherBytes.Length);

            return result;
        }

        private byte[] DecryptBytes(byte[] fullCipher, string key)
        {
            using var aes = Aes.Create();
            aes.Key = Convert.FromBase64String(key);

            var iv = new byte[aes.BlockSize / 8];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, cipher.Length);

            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
        }
    }
}
