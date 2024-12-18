namespace SecureVault.Core.Interfaces
{
    public interface IKeyManagementService
    {
        Task<string> GenerateKeyAsync();
        Task<bool> ValidateKeyAsync(string key);
        Task<bool> RotateKeyAsync(string oldKey, string newKey);
        Task<string> GenerateMasterKeyAsync();
        Task<string> DeriveKeyFromPasswordAsync(string password, string salt);
        Task<string> GetCurrentKeyAsync();
        Task<bool> InitializeKeysAsync();
        Task<bool> BackupKeysAsync(string path);
        Task<bool> RestoreKeysAsync(string path);
        Task<string> EncryptKeyAsync(string key, string masterKey);
        Task<string> DecryptKeyAsync(string encryptedKey, string masterKey);
    }
}
