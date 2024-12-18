using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;

namespace SecureVault.Web.Pages.Backups
{
    public class IndexModel : PageModel
    {
        private readonly IBackupService _backupService;
        private readonly IDatabaseService _databaseService;
        private readonly IBackupCredentialService _backupCredentialService;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<IndexModel> _logger;

        public List<BackupInfoViewModel> Backups { get; set; } = new();
        public BackupStatistics Statistics { get; set; } = new();
        public BackupConfiguration AutoBackupConfig { get; set; } = new();

        public IndexModel(
            IBackupService backupService,
            IDatabaseService databaseService,
            IBackupCredentialService backupCredentialService,
            IAuditLogService auditLogService,
            ILogger<IndexModel> logger)
        {
            _backupService = backupService;
            _databaseService = databaseService;
            _backupCredentialService = backupCredentialService;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task OnGetAsync()
        {
            await LoadBackupDataAsync();
        }

        public async Task<IActionResult> OnPostCreateBackupAsync(string backupPassword)
        {
            try
            {
                var userId = User.GetUserId(); // Implement this extension method
                var backupPath = await _backupService.CreateBackupAsync(userId, backupPassword);
                
                // Store the backup password
                await _backupCredentialService.StoreBackupPasswordAsync(backupPath, backupPassword, userId);

                // Verify the backup
                if (!await _backupService.VerifyBackupAsync(backupPath))
                {
                    throw new Exception("Backup verification failed");
                }

                await _auditLogService.LogEventAsync(
                    userId,
                    AuditEventType.SecuritySettingUpdated,
                    "Manual backup created successfully"
                );

                TempData["SuccessMessage"] = "Backup created successfully";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create backup");
                TempData["ErrorMessage"] = "Failed to create backup: " + ex.Message;
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostConfigureAutoBackupAsync(BackupConfiguration config)
        {
            try
            {
                var interval = TimeSpan.FromDays(config.Interval);
                await _backupService.ConfigureAutomaticBackupAsync(interval, config.Location);
                TempData["SuccessMessage"] = "Automatic backup configured successfully";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to configure automatic backup");
                TempData["ErrorMessage"] = "Failed to configure automatic backup: " + ex.Message;
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostRestoreAsync(string id)
        {
            try
            {
                var backup = await GetBackupByIdAsync(id);
                if (backup == null)
                    return NotFound();

                var password = await _backupCredentialService.GetBackupPasswordAsync(backup.Path);
                if (password == null)
                    throw new Exception("Backup password not found");

                await _backupService.RestoreBackupAsync(backup.Path, password);

                var userId = User.GetUserId();
                await _auditLogService.LogEventAsync(
                    userId,
                    AuditEventType.SecuritySettingUpdated,
                    $"Backup restored: {backup.FileName}"
                );

                TempData["SuccessMessage"] = "Backup restored successfully";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to restore backup");
                TempData["ErrorMessage"] = "Failed to restore backup: " + ex.Message;
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostVerifyAsync(string id)
        {
            try
            {
                var backup = await GetBackupByIdAsync(id);
                if (backup == null)
                    return NotFound();

                if (await _backupService.VerifyBackupAsync(backup.Path))
                {
                    TempData["SuccessMessage"] = "Backup verified successfully";
                }
                else
                {
                    TempData["ErrorMessage"] = "Backup verification failed";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to verify backup");
                TempData["ErrorMessage"] = "Failed to verify backup: " + ex.Message;
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDeleteAsync(string id)
        {
            try
            {
                var backup = await GetBackupByIdAsync(id);
                if (backup == null)
                    return NotFound();

                // Delete the backup file
                System.IO.File.Delete(backup.Path);

                // Delete the backup password
                await _backupCredentialService.DeleteBackupPasswordAsync(backup.Path);

                var userId = User.GetUserId();
                await _auditLogService.LogEventAsync(
                    userId,
                    AuditEventType.SecuritySettingUpdated,
                    $"Backup deleted: {backup.FileName}"
                );

                TempData["SuccessMessage"] = "Backup deleted successfully";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete backup");
                TempData["ErrorMessage"] = "Failed to delete backup: " + ex.Message;
            }

            return RedirectToPage();
        }

        private async Task LoadBackupDataAsync()
        {
            try
            {
                // Load backups
                var backupFiles = await _backupService.ListBackupsAsync();
                Backups.Clear();

                foreach (var backupPath in backupFiles)
                {
                    var metadata = await _backupService.GetBackupMetadataAsync(backupPath);
                    var fileInfo = new System.IO.FileInfo(backupPath);

                    Backups.Add(new BackupInfoViewModel
                    {
                        Id = metadata.Id,
                        FileName = metadata.FileName,
                        Path = backupPath,
                        CreatedAt = fileInfo.CreationTime,
                        CreatedBy = metadata.UserId,
                        SizeInBytes = fileInfo.Length,
                        IsVerified = await _backupService.VerifyBackupAsync(backupPath),
                        Status = metadata.Status
                    });
                }

                // Load statistics
                Statistics = new BackupStatistics
                {
                    TotalBackups = Backups.Count,
                    TotalSizeBytes = Backups.Sum(b => b.SizeInBytes),
                    LastBackupTime = Backups.Any() ? Backups.Max(b => b.CreatedAt) : null,
                    SuccessfulVerifications = Backups.Count(b => b.IsVerified),
                    FailedVerifications = Backups.Count(b => !b.IsVerified)
                };

                // Load auto-backup configuration
                AutoBackupConfig = await _databaseService.GetBackupConfigurationAsync()
                    ?? new BackupConfiguration();

                if (AutoBackupConfig.Interval > TimeSpan.Zero)
                {
                    Statistics.NextScheduledBackup = Statistics.LastBackupTime?.Add(AutoBackupConfig.Interval);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load backup data");
                TempData["ErrorMessage"] = "Failed to load backup data: " + ex.Message;
            }
        }

        private async Task<BackupInfoViewModel?> GetBackupByIdAsync(string id)
        {
            await LoadBackupDataAsync();
            return Backups.FirstOrDefault(b => b.Id == id);
        }

        public string FormatSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;

            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }

            return $"{size:0.##} {sizes[order]}";
        }
    }
}
