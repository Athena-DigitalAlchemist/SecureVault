namespace SecureVault.Core.Interfaces
{
    public interface IBackupCredentialService
    {
        Task<bool> StoreBackupPasswordAsync(string backupPath, string encryptedPassword);
        Task<string?> GetBackupPasswordAsync(string backupPath);
        Task<bool> ValidateBackupPasswordAsync(string backupPath, string password);
        Task<bool> DeleteBackupPasswordAsync(string backupPath);
    }
}