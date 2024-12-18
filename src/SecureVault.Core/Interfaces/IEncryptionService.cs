namespace SecureVault.Core.Interfaces
{
    public interface IEncryptionService
    {
        Task<string> EncryptAsync(string plainText, string key);
        Task<string> DecryptAsync(string cipherText, string key);
        string Encrypt(string plainText, string key);
        string Decrypt(string cipherText, string key);
        string ReEncrypt(string cipherText, string oldKey, string newKey);
        Task<string> GenerateSaltAsync();
        string GenerateSalt();
        Task<string> HashPasswordAsync(string password, string salt);
        string HashPassword(string password, string salt);
        Task<bool> VerifyPasswordAsync(string password, string hash, string salt);
        bool VerifyPassword(string password, string hash, string salt);
        Task<string> GenerateKeyAsync();
        string GenerateKey();
        Task<string> DeriveKeyAsync(string password, string salt, int iterations = 100000);
        string DeriveKey(string password, string salt, int iterations = 100000);
        Task<bool> ValidateKeyAsync(string key);
        bool ValidateKey(string key);
        Task<bool> ValidateKeyStrengthAsync(string key);
        Task<string> EncryptFileAsync(string filePath, string key);
        string EncryptFile(string filePath, string key);
        Task<string> DecryptFileAsync(string filePath, string key);
        string DecryptFile(string filePath, string key);
        Task<string> EncryptStreamAsync(Stream stream, string key);
        Task<Stream> DecryptStreamAsync(Stream stream, string key);
        Task<string> GenerateHashAsync(string input);
        string GenerateHash(string input);
        Task<string> GenerateRandomPasswordAsync(int length = 16, bool useSpecialChars = true);
        string GenerateRandomPassword(int length = 16, bool useSpecialChars = true);
        Task<byte[]> GenerateRandomBytesAsync(int length);
        Task<string> UpdateMasterKeyAsync(string oldKey, string newKey);
        Task<string> GenerateMasterKeyAsync(string password);
        Task<bool> ValidatePasswordAsync(string password);
        Task<string> GenerateMasterKeyAsync();
    }
}
