using System.IO.Compression;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;

namespace SecureVault.Core.Services
{
    public class BackupService : IBackupService
    {
        private readonly ILogger<BackupService> _logger;
        private readonly IDatabaseService _databaseService;
        private readonly IEncryptionService _encryptionService;
        private readonly string _backupDirectory;

        public BackupService(
            ILogger<BackupService> logger,
            IDatabaseService databaseService,
            IEncryptionService encryptionService,
            string backupDirectory)
        {
            _logger = logger;
            _databaseService = databaseService;
            _encryptionService = encryptionService;
            _backupDirectory = backupDirectory;

            if (!Directory.Exists(_backupDirectory))
            {
                Directory.CreateDirectory(_backupDirectory);
            }
        }

        public async Task<bool> CreateBackupAsync(string userId)
        {
            try
            {
                var config = await _databaseService.GetBackupConfigurationAsync();
                var backupPath = Path.Combine(_backupDirectory, $"backup_{DateTime.UtcNow:yyyyMMddHHmmss}.zip");

                // Create backup metadata
                var metadata = new BackupMetadata
                {
                    UserId = userId,
                    FileName = Path.GetFileName(backupPath),
                    FilePath = backupPath,
                    Status = "InProgress",
                    CreatedAt = DateTime.UtcNow,
                    LastModified = DateTime.UtcNow,
                    IsAutomatic = false
                };

                // Create backup
                using (var archive = ZipFile.Open(backupPath, ZipArchiveMode.Create))
                {
                    // Add database backup
                    var dbBackupPath = Path.Combine(_backupDirectory, "temp_db_backup.db");
                    await _databaseService.BackupDatabaseAsync(dbBackupPath);
                    archive.CreateEntryFromFile(dbBackupPath, "database.db");
                    File.Delete(dbBackupPath);

                    // Add metadata
                    metadata.Size = new FileInfo(backupPath).Length;
                    metadata.Hash = _encryptionService.GenerateHash(File.ReadAllBytes(backupPath).ToString());
                }

                // Encrypt backup if configured
                if (config.EncryptBackups)
                {
                    var encryptedPath = _encryptionService.EncryptFile(backupPath, await GetBackupKeyAsync(userId));
                    File.Delete(backupPath);
                    metadata.EncryptedPath = encryptedPath;
                    metadata.IsEncrypted = true;
                }

                // Update metadata
                metadata.Status = "Completed";
                metadata.CompletedAt = DateTime.UtcNow;
                await _databaseService.SaveBackupMetadataAsync(metadata);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create backup");
                return false;
            }
        }

        public async Task<bool> RestoreBackupAsync(string backupId)
        {
            try
            {
                var metadata = await _databaseService.GetBackupMetadataByIdAsync(int.Parse(backupId));
                var backupPath = metadata.EncryptedPath ?? metadata.FilePath;

                if (!File.Exists(backupPath))
                {
                    throw new FileNotFoundException("Backup file not found", backupPath);
                }

                // Decrypt if necessary
                var workingPath = backupPath;
                if (metadata.IsEncrypted)
                {
                    workingPath = _encryptionService.DecryptFile(backupPath, await GetBackupKeyAsync(metadata.UserId));
                }

                // Extract and restore
                using (var archive = ZipFile.OpenRead(workingPath))
                {
                    var dbEntry = archive.GetEntry("database.db");
                    var tempPath = Path.Combine(_backupDirectory, "temp_restore.db");
                    dbEntry.ExtractToFile(tempPath, true);

                    await _databaseService.RestoreDatabaseAsync(tempPath);
                    File.Delete(tempPath);
                }

                // Cleanup
                if (metadata.IsEncrypted && workingPath != backupPath)
                {
                    File.Delete(workingPath);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to restore backup");
                return false;
            }
        }

        public async Task<bool> DeleteBackupAsync(string backupId)
        {
            try
            {
                var metadata = await _databaseService.GetBackupMetadataByIdAsync(int.Parse(backupId));

                // Delete physical files
                if (!string.IsNullOrEmpty(metadata.EncryptedPath) && File.Exists(metadata.EncryptedPath))
                {
                    File.Delete(metadata.EncryptedPath);
                }
                if (!string.IsNullOrEmpty(metadata.FilePath) && File.Exists(metadata.FilePath))
                {
                    File.Delete(metadata.FilePath);
                }

                // Delete metadata
                return await _databaseService.DeleteBackupMetadataAsync(metadata.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete backup");
                return false;
            }
        }

        public async Task<List<string>> ListBackupsAsync(string userId)
        {
            try
            {
                var backups = await _databaseService.GetBackupHistoryAsync(userId);
                return backups.Select(b => b.Id.ToString()).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to list backups");
                return new List<string>();
            }
        }

        public async Task<bool> ValidateBackupAsync(string backupId)
        {
            try
            {
                var metadata = await _databaseService.GetBackupMetadataByIdAsync(int.Parse(backupId));
                var backupPath = metadata.EncryptedPath ?? metadata.FilePath;

                if (!File.Exists(backupPath))
                {
                    return false;
                }

                var currentHash = _encryptionService.GenerateHash(File.ReadAllBytes(backupPath).ToString());
                return currentHash == metadata.Hash;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate backup");
                return false;
            }
        }

        public async Task<bool> ScheduleBackupAsync(string userId, DateTime scheduleTime)
        {
            try
            {
                var config = await _databaseService.GetBackupConfigurationAsync();
                config.AutoBackupEnabled = true;
                config.BackupFrequencyDays = (int)(scheduleTime - DateTime.UtcNow).TotalDays;
                await _databaseService.UpdateBackupConfigurationAsync(config);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to schedule backup");
                return false;
            }
        }

        public async Task<bool> ConfigureBackupAsync(string userId, string backupPath, bool autoBackup)
        {
            try
            {
                var config = await _databaseService.GetBackupConfigurationAsync();
                config.BackupPath = backupPath;
                config.AutoBackupEnabled = autoBackup;
                await _databaseService.UpdateBackupConfigurationAsync(config);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to configure backup");
                return false;
            }
        }

        public async Task<bool> VerifyBackupIntegrityAsync(string backupId)
        {
            try
            {
                var metadata = await _databaseService.GetBackupMetadataByIdAsync(int.Parse(backupId));
                var backupPath = metadata.EncryptedPath ?? metadata.FilePath;

                if (!File.Exists(backupPath))
                {
                    return false;
                }

                using var archive = ZipFile.OpenRead(backupPath);
                var dbEntry = archive.GetEntry("database.db");
                return dbEntry != null && dbEntry.Length > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to verify backup integrity");
                return false;
            }
        }

        public async Task<bool> ExportBackupAsync(string backupId, string exportPath)
        {
            try
            {
                var metadata = await _databaseService.GetBackupMetadataByIdAsync(int.Parse(backupId));
                var backupPath = metadata.EncryptedPath ?? metadata.FilePath;

                if (!File.Exists(backupPath))
                {
                    return false;
                }

                File.Copy(backupPath, exportPath, true);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to export backup");
                return false;
            }
        }

        public async Task<bool> ImportBackupAsync(string importPath)
        {
            try
            {
                if (!File.Exists(importPath))
                {
                    return false;
                }

                var fileName = Path.GetFileName(importPath);
                var newPath = Path.Combine(_backupDirectory, fileName);
                File.Copy(importPath, newPath, true);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to import backup");
                return false;
            }
        }

        private async Task<string> GetBackupKeyAsync(string userId)
        {
            var credential = await _databaseService.GetBackupCredentialAsync(userId);
            return credential.EncryptedPassword;
        }
    }
}
