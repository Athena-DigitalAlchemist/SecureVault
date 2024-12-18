using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;

namespace SecureVault.Core.Services
{
    public class AutomaticBackupService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<AutomaticBackupService> _logger;
        private Timer? _timer;

        public AutomaticBackupService(
            IServiceProvider serviceProvider,
            ILogger<AutomaticBackupService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await DoWork(stoppingToken);
        }

        private async Task DoWork(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    using var scope = _serviceProvider.CreateScope();
                    var databaseService = scope.ServiceProvider.GetRequiredService<IDatabaseService>();
                    var backupService = scope.ServiceProvider.GetRequiredService<IBackupService>();
                    var auditLogService = scope.ServiceProvider.GetRequiredService<IAuditLogService>();
                    var backupCredentialService = scope.ServiceProvider.GetRequiredService<IBackupCredentialService>();

                    var config = await databaseService.GetBackupConfigurationAsync();
                    if (config == null || !config.IsEnabled)
                    {
                        // No configuration or disabled, check again in 1 hour
                        await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
                        continue;
                    }

                    var now = DateTime.UtcNow;
                    var nextBackupDue = config.LastBackup + config.Interval;

                    if (now >= nextBackupDue)
                    {
                        try
                        {
                            // Create backup using a system-generated password
                            var backupPassword = GenerateBackupPassword();
                            var backupPath = await backupService.CreateBackupAsync("system", backupPassword);

                            // Store the backup password securely
                            await backupCredentialService.StoreBackupPasswordAsync(backupPath, backupPassword, "system");

                            // Verify the backup
                            if (!await backupService.VerifyBackupAsync(backupPath))
                            {
                                throw new Exception("Backup verification failed");
                            }

                            // Update last backup time
                            await databaseService.UpdateLastBackupTimeAsync(config.Id, now);

                            await auditLogService.LogEventAsync(
                                "system",
                                AuditEventType.SecuritySettingUpdated,
                                $"Automatic backup created and verified at {backupPath}"
                            );
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Failed to create automatic backup");
                            await auditLogService.LogEventAsync(
                                "system",
                                AuditEventType.SecuritySettingUpdated,
                                $"Automatic backup failed: {ex.Message}"
                            );
                        }

                        // Clean up old backups
                        await CleanupOldBackupsAsync();
                    }

                    // Calculate delay until next check (minimum 1 minute)
                    var delay = nextBackupDue - now;
                    if (delay < TimeSpan.FromMinutes(1))
                        delay = TimeSpan.FromMinutes(1);

                    await Task.Delay(delay, stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in automatic backup service");
                    await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
                }
            }
        }

        private string GenerateBackupPassword()
        {
            // Generate a cryptographically secure random password
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
            var random = new Random();
            var password = new char[32];

            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                var bytes = new byte[32];
                rng.GetBytes(bytes);

                for (int i = 0; i < password.Length; i++)
                {
                    password[i] = chars[bytes[i] % chars.Length];
                }
            }

            return new string(password);
        }

        private async Task StoreBackupPasswordAsync(string backupPath, string password)
        {
            // This is a placeholder - implement secure password storage according to your requirements
            // For example, you might want to:
            // 1. Store it in a secure key vault
            // 2. Encrypt it with a master key
            // 3. Store it in a separate secure database
            // 4. Send it to administrators via secure channels
            _logger.LogInformation($"Backup password for {backupPath} needs to be stored securely");
        }

        private async Task CleanupOldBackupsAsync()
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();
                var backupService = scope.ServiceProvider.GetRequiredService<IBackupService>();
                var databaseService = scope.ServiceProvider.GetRequiredService<IDatabaseService>();

                var config = await databaseService.GetBackupConfigurationAsync();
                if (config == null) return;

                var backups = await backupService.ListBackupsAsync();
                var maxBackups = 10; // Configure this based on your requirements

                if (backups.Count <= maxBackups) return;

                // Sort backups by date (assuming the filename contains the date)
                backups.Sort((a, b) => string.Compare(b, a)); // Descending order

                // Delete old backups
                for (int i = maxBackups; i < backups.Count; i++)
                {
                    try
                    {
                        System.IO.File.Delete(backups[i]);
                        _logger.LogInformation($"Deleted old backup: {backups[i]}");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Failed to delete old backup: {backups[i]}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cleaning up old backups");
            }
        }

        public override async Task StopAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Automatic backup service is stopping");
            _timer?.Change(Timeout.Infinite, 0);
            await base.StopAsync(stoppingToken);
        }

        public override void Dispose()
        {
            _timer?.Dispose();
            base.Dispose();
        }
    }
}
