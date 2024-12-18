using SecureVault.Core.Models;
using SecureVault.Core.Enums;

namespace SecureVault.Core.Interfaces
{
    public interface IDatabaseService : IAuditLogService
    {
        Task InitializeDatabaseAsync();
        Task CreateTablesAsync();
        Task<bool> BackupDatabaseAsync(string backupPath);
        Task<bool> RestoreDatabaseAsync(string backupPath);
        Task UpdateSecuritySettingAsync(string setting, string? value);
        Task InitializeAsync(string encryptedVerification);
        Task InitializeNewUserAsync(string userId, string passwordHash, string salt);
        Task<string> GetVerificationDataAsync();
        Task<bool> ValidateUserCredentialsAsync(string username, string passwordHash);
        Task<string> GetUserSaltAsync(string username);
        Task UpdatePasswordHashAsync(string username, string newPasswordHash);
        Task<string> RetrieveSecuritySettingAsync(string key);
        Task ReEncryptAllDataAsync(string userId, string newMasterKey);
        Task<List<PasswordEntry>> GetAllPasswordsAsync(string userId);
        Task<List<PasswordEntry>> GetPasswordsByCategoryAsync(string userId, string category);
        Task<int> SavePasswordAsync(PasswordEntry password);
        Task DeletePasswordAsync(int passwordId);
        Task<List<SecureNote>> GetNotesAsync(string userId);
        Task<List<SecureNote>> GetAllNotesAsync();
        Task<int> SaveNoteAsync(SecureNote note);
        Task DeleteNoteAsync(int noteId);
        Task<List<SecureFile>> GetSecureFilesAsync(string userId);
        Task<SecureFile> GetSecureFileAsync(int fileId);
        Task<int> SaveSecureFileAsync(SecureFile file, string userId);
        Task DeleteSecureFileAsync(int fileId);
        Task<List<BackupMetadata>> GetBackupHistoryAsync(string userId);
        Task<bool> DeleteBackupMetadataAsync(int backupId);
        Task<UserSettings> GetUserSettingsAsync(string userId);
        Task<bool> SaveUserSettingsAsync(string userId, UserSettings settings);
        Task<bool> UpdateUserSettingsAsync(string userId, UserSettings settings);
        Task<bool> SaveBackupMetadataAsync(BackupMetadata metadata);
        Task UpdateVerificationDataAsync(string data);
        Task<BackupConfiguration> GetBackupConfigurationAsync();
        Task UpdateBackupConfigurationAsync(BackupConfiguration config);
        Task<User> GetUserByIdAsync(string userId);
        Task<User> GetUserByUsernameAsync(string username);
        Task<User> GetUserByEmailAsync(string email);
        Task<bool> CreateUserAsync(User user);
        Task<bool> UpdateUserAsync(User user);
        Task<bool> DeleteUserAsync(string userId);
        Task<BackupMetadata> GetBackupMetadataByIdAsync(int id);
        Task<bool> UpdateBackupMetadataAsync(BackupMetadata metadata);
        Task UpdateLastBackupTimeAsync(DateTime lastBackupTime);
        Task<bool> SaveBackupCredentialAsync(BackupCredential credential);
        Task<BackupCredential> GetBackupCredentialAsync(string userId);
        Task<bool> DeleteBackupCredentialAsync(string userId);
        Task<bool> UpdatePasswordAsync(string userId, int passwordId, PasswordEntry password);
    }
}
