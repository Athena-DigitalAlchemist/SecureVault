using SecureVault.Core.Models;

namespace SecureVault.Core.Interfaces
{
    public interface IBackupService
    {
        Task<bool> CreateBackupAsync(string userId);
        Task<bool> CreateBackupAsync(string userId, string backupPath);
        Task<bool> RestoreBackupAsync(string backupId);
        Task<bool> DeleteBackupAsync(string backupId);
        Task<List<string>> ListBackupsAsync(string userId);
        Task<bool> ValidateBackupAsync(string backupId);
        Task<bool> ScheduleBackupAsync(string userId, DateTime scheduleTime);
        Task<bool> ConfigureBackupAsync(string userId, string backupPath, bool autoBackup);
        Task<bool> VerifyBackupIntegrityAsync(string backupId);
        Task<bool> ExportBackupAsync(string backupId, string exportPath);
        Task<bool> ImportBackupAsync(string importPath);
        Task<bool> VerifyBackupAsync(string backupId);
        Task<BackupMetadata> GetBackupMetadataAsync(string backupId);
        Task<bool> SaveBackupCredentialAsync(string userId, string backupPath, string encryptedPassword);
        Task<string> GetBackupCredentialAsync(string userId, string backupPath);
        Task<bool> DeleteBackupCredentialAsync(string userId, string backupPath);
        Task<bool> VerifyBackupAsync(BackupMetadata metadata);
        Task<bool> CreateBackupAsync(BackupConfiguration config);
        Task<bool> RestoreBackupAsync(BackupConfiguration config);
        Task<bool> VerifyBackupAsync(BackupConfiguration config);
        Task<bool> SaveBackupCredentialAsync(BackupCredential credential);
        Task<BackupCredential> GetBackupCredentialAsync(BackupConfiguration config);
        Task<bool> DeleteBackupCredentialAsync(BackupConfiguration config);
    }
}
