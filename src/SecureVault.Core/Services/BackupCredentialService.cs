using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;

namespace SecureVault.Core.Services
{
    public class BackupCredentialService : IBackupCredentialService
    {
        private readonly IDatabaseService _databaseService;
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<BackupCredentialService> _logger;

        public BackupCredentialService(
            IDatabaseService databaseService,
            IEncryptionService encryptionService,
            ILogger<BackupCredentialService> logger)
        {
            _databaseService = databaseService;
            _encryptionService = encryptionService;
            _logger = logger;
        }

        public async Task<bool> StoreBackupPasswordAsync(string backupPath, string encryptedPassword)
        {
            try
            {
                var userId = await GetCurrentUserIdAsync();
                return await _databaseService.SaveBackupCredentialAsync(userId, backupPath, encryptedPassword);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to store backup password for path {BackupPath}", backupPath);
                return false;
            }
        }

        public async Task<string?> GetBackupPasswordAsync(string backupPath)
        {
            try
            {
                var userId = await GetCurrentUserIdAsync();
                return await _databaseService.GetBackupCredentialAsync(userId, backupPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get backup password for path {BackupPath}", backupPath);
                return null;
            }
        }

        public async Task<bool> ValidateBackupPasswordAsync(string backupPath, string password)
        {
            try
            {
                var storedPassword = await GetBackupPasswordAsync(backupPath);
                if (string.IsNullOrEmpty(storedPassword))
                {
                    return false;
                }

                var decryptedStoredPassword = await _encryptionService.DecryptAsync(storedPassword, await GetEncryptionKeyAsync());
                return decryptedStoredPassword == password;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate backup password for path {BackupPath}", backupPath);
                return false;
            }
        }

        public async Task<bool> DeleteBackupPasswordAsync(string backupPath)
        {
            try
            {
                var userId = await GetCurrentUserIdAsync();
                return await _databaseService.DeleteBackupCredentialAsync(userId, backupPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete backup password for path {BackupPath}", backupPath);
                return false;
            }
        }

        private Task<string> GetCurrentUserIdAsync()
        {
            throw new NotImplementedException("GetCurrentUserIdAsync needs to be implemented");
        }

        private Task<string> GetEncryptionKeyAsync()
        {
            throw new NotImplementedException("GetEncryptionKeyAsync needs to be implemented");
        }
    }
}

