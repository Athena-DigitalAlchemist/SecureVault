using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Services;

namespace SecureVault.Core.DependencyInjection
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddSecureVaultCore(
            this IServiceCollection services,
            string baseStoragePath,
            IConfiguration configuration)
        {
            // Configuration
            var dataDirectory = configuration["DataDirectory"];
            var databasePath = Path.Combine(dataDirectory, "securevault.db");
            var userDirectory = Path.Combine(dataDirectory, "users");
            var migrationsPath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Database",
                "Migrations"
            );

            var secureStoragePath = Path.Combine(baseStoragePath, "secure_storage");
            var backupPath = Path.Combine(baseStoragePath, "backups");
            var tempPath = Path.Combine(baseStoragePath, "temp");

            // Ensure directories exist
            Directory.CreateDirectory(dataDirectory);
            Directory.CreateDirectory(userDirectory);
            Directory.CreateDirectory(secureStoragePath);
            Directory.CreateDirectory(backupPath);
            Directory.CreateDirectory(tempPath);

            // Core services
            services.AddSingleton<SecureVault.Core.Interfaces.IKeyManagementService, KeyManagementService>();
            services.AddSingleton<SecureVault.Core.Interfaces.IEncryptionService, EncryptionService>();
            services.AddSingleton<SecureVault.Core.Interfaces.IHashingService, HashingService>();

            // Database and storage services
            services.AddScoped<SecureVault.Core.Interfaces.IDatabaseService>(provider =>
                new DatabaseService(
                    databasePath,
                    userDirectory,
                    provider.GetRequiredService<SecureVault.Core.Interfaces.IEncryptionService>(),
                    provider.GetRequiredService<ILogger<DatabaseService>>()
                )
            );

            services.AddScoped<SecureVault.Core.Interfaces.ISecureFileStorageService, SecureFileStorageService>();
            services.AddScoped<SecureVault.Core.Interfaces.IUserService, UserService>();
            services.AddScoped<SecureVault.Core.Interfaces.IAuthenticationService, AuthenticationService>();
            services.AddScoped<SecureVault.Core.Interfaces.ITwoFactorAuthService, TwoFactorAuthService>();
            services.AddScoped<SecureVault.Core.Interfaces.IPasswordResetService, PasswordResetService>();
            services.AddScoped<SecureVault.Core.Interfaces.IPasswordService, PasswordService>();
            services.AddScoped<SecureVault.Core.Interfaces.IMigrationService, MigrationService>();
            services.AddScoped<SecureVault.Core.Interfaces.IDataPortabilityService, DataPortabilityService>();
            services.AddScoped<SecureVault.Core.Interfaces.IBackupService, BackupService>();
            services.AddScoped<SecureVault.Core.Interfaces.IAuditLogService, AuditLogService>();
            services.AddScoped<SecureVault.Core.Interfaces.IEmailService, EmailService>();
            services.AddScoped<SecureVault.Core.Interfaces.IBackupCredentialService, BackupCredentialService>();

            // Configure SMTP settings
            services.Configure<SmtpSettings>(configuration.GetSection("SmtpSettings"));

            return services;
        }
    }

    public class SmtpSettings
    {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string FromEmail { get; set; } = string.Empty;
        public string FromName { get; set; } = string.Empty;
        public bool EnableSsl { get; set; }
    }
}
