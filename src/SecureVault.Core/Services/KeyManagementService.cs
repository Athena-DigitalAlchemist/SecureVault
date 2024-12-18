using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;

namespace SecureVault.Core.Services
{
    public class KeyManagementService : IKeyManagementService
    {
        private readonly IEncryptionService _encryptionService;
        private readonly IDatabaseService _databaseService;
        private readonly ILogger<KeyManagementService> _logger;
        private const int KEY_SIZE = 32;
        private const int ITERATIONS = 100000;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualUnlock(IntPtr lpAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_RELEASE = 0x8000;
        private const uint PAGE_READWRITE = 0x04;

        public KeyManagementService(
            IEncryptionService encryptionService,
            IDatabaseService databaseService,
            ILogger<KeyManagementService> logger)
        {
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
            _databaseService = databaseService ?? throw new ArgumentNullException(nameof(databaseService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<string> GenerateKeyAsync()
        {
            try
            {
                var key = new byte[KEY_SIZE];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(key);
                }
                return Convert.ToBase64String(key);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate key");
                throw;
            }
        }

        public async Task<string> GenerateMasterKeyAsync()
        {
            try
            {
                return await GenerateKeyAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate master key");
                throw;
            }
        }

        public async Task<string> DeriveKeyFromPasswordAsync(string password, string salt)
        {
            try
            {
                using var pbkdf2 = new Rfc2898DeriveBytes(
                    password,
                    Convert.FromBase64String(salt),
                    ITERATIONS,
                    HashAlgorithmName.SHA256);

                return Convert.ToBase64String(pbkdf2.GetBytes(KEY_SIZE));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to derive key from password");
                throw;
            }
        }

        public async Task<bool> ValidateKeyAsync(string key)
        {
            try
            {
                if (string.IsNullOrEmpty(key))
                    return false;

                var verificationData = await _databaseService.GetVerificationDataAsync();
                if (string.IsNullOrEmpty(verificationData))
                    return true;

                return await _encryptionService.ValidateKeyAsync(key);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate key");
                return false;
            }
        }

        public async Task<bool> RotateKeyAsync(string oldKey, string newKey)
        {
            try
            {
                if (!await ValidateKeyAsync(oldKey))
                    return false;

                if (!await _encryptionService.ValidateKeyStrengthAsync(newKey))
                    return false;

                await _databaseService.ReEncryptAllDataAsync(oldKey, newKey);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to rotate key");
                return false;
            }
        }

        public async Task<string> GetCurrentKeyAsync()
        {
            try
            {
                var verificationData = await _databaseService.GetVerificationDataAsync();
                if (string.IsNullOrEmpty(verificationData))
                    throw new InvalidOperationException("No current key found");

                return verificationData;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get current key");
                throw;
            }
        }

        public async Task<bool> InitializeKeysAsync()
        {
            try
            {
                var masterKey = await GenerateMasterKeyAsync();
                var verificationData = await _encryptionService.GenerateKeyAsync();
                await _databaseService.UpdateVerificationDataAsync(verificationData);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize keys");
                return false;
            }
        }

        public async Task<bool> BackupKeysAsync(string path)
        {
            try
            {
                var currentKey = await GetCurrentKeyAsync();
                var encryptedKey = await _encryptionService.EncryptAsync(currentKey, await GenerateMasterKeyAsync());
                await File.WriteAllBytesAsync(path, encryptedKey);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to backup keys");
                return false;
            }
        }

        public async Task<bool> RestoreKeysAsync(string path)
        {
            try
            {
                if (!File.Exists(path))
                    return false;

                var encryptedKey = await File.ReadAllBytesAsync(path);
                var masterKey = await GenerateMasterKeyAsync();
                var restoredKey = await _encryptionService.DecryptAsync(encryptedKey, masterKey);
                await _databaseService.UpdateVerificationDataAsync(restoredKey);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to restore keys");
                return false;
            }
        }

        public async Task<string> EncryptKeyAsync(string key, string masterKey)
        {
            try
            {
                var keyBytes = Convert.FromBase64String(key);
                var masterKeyBytes = Convert.FromBase64String(masterKey);
                using var aes = Aes.Create();
                aes.Key = masterKeyBytes;
                aes.GenerateIV();

                using var msEncrypt = new MemoryStream();
                await msEncrypt.WriteAsync(aes.IV, 0, aes.IV.Length);

                using (var cryptoStream = new CryptoStream(msEncrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                using (var writer = new BinaryWriter(cryptoStream))
                {
                    writer.Write(keyBytes);
                }

                return Convert.ToBase64String(msEncrypt.ToArray());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to encrypt key");
                throw;
            }
        }

        public async Task<string> DecryptKeyAsync(string encryptedKey, string masterKey)
        {
            try
            {
                var encryptedKeyBytes = Convert.FromBase64String(encryptedKey);
                var masterKeyBytes = Convert.FromBase64String(masterKey);
                using var aes = Aes.Create();
                aes.Key = masterKeyBytes;

                using var msDecrypt = new MemoryStream(encryptedKeyBytes);
                var iv = new byte[16];
                await msDecrypt.ReadAsync(iv, 0, iv.Length);
                aes.IV = iv;

                using var cryptoStream = new CryptoStream(msDecrypt, aes.CreateDecryptor(), CryptoStreamMode.Read);
                using var reader = new BinaryReader(cryptoStream);
                var decryptedKey = reader.ReadBytes(KEY_SIZE);

                return Convert.ToBase64String(decryptedKey);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to decrypt key");
                throw;
            }
        }
    }
}
