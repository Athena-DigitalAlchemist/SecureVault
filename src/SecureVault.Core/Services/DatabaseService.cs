using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Enums;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecureVault.Core.Services
{
    public class DatabaseService : IDatabaseService, IAuditLogService
    {
        private readonly string _connectionString;
        private readonly ILogger<DatabaseService> _logger;
        private readonly IEncryptionService _encryptionService;

        public DatabaseService(
            string connectionString,
            ILogger<DatabaseService> logger,
            IEncryptionService encryptionService)
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
        }

        // Βοηθητικές μέθοδοι επικύρωσης
        private void ValidateUser(User user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            
            if (string.IsNullOrEmpty(user.Id))
                throw new ArgumentException("User ID cannot be empty", nameof(user));
            
            if (string.IsNullOrEmpty(user.Username))
                throw new ArgumentException("Username cannot be empty", nameof(user));
            
            if (!ValidateEmail(user.Email))
                throw new ArgumentException("Invalid email format", nameof(user));
            
            if (string.IsNullOrEmpty(user.PasswordHash))
                throw new ArgumentException("Password hash cannot be empty", nameof(user));
        }

        private void ValidatePasswordEntry(PasswordEntry entry)
        {
            if (entry == null)
                throw new ArgumentNullException(nameof(entry));
            
            if (string.IsNullOrEmpty(entry.UserId))
                throw new ArgumentException("User ID cannot be empty", nameof(entry));
            
            if (string.IsNullOrEmpty(entry.Title))
                throw new ArgumentException("Title cannot be empty", nameof(entry));
            
            if (string.IsNullOrEmpty(entry.EncryptedPassword))
                throw new ArgumentException("Encrypted password cannot be empty", nameof(entry));
        }

        private void ValidateSecureFile(SecureFile file)
        {
            if (file == null)
                throw new ArgumentNullException(nameof(file));
            
            if (string.IsNullOrEmpty(file.UserId))
                throw new ArgumentException("User ID cannot be empty", nameof(file));
            
            if (string.IsNullOrEmpty(file.FileName))
                throw new ArgumentException("File name cannot be empty", nameof(file));
            
            if (string.IsNullOrEmpty(file.FilePath))
                throw new ArgumentException("File path cannot be empty", nameof(file));
            
            if (string.IsNullOrEmpty(file.Hash))
                throw new ArgumentException("File hash cannot be empty", nameof(file));
        }

        private void ValidateBackupMetadata(BackupMetadata metadata)
        {
            if (metadata == null)
                throw new ArgumentNullException(nameof(metadata));
            
            if (string.IsNullOrEmpty(metadata.UserId))
                throw new ArgumentException("User ID cannot be empty", nameof(metadata));
            
            if (string.IsNullOrEmpty(metadata.FileName))
                throw new ArgumentException("File name cannot be empty", nameof(metadata));
            
            if (string.IsNullOrEmpty(metadata.FilePath))
                throw new ArgumentException("File path cannot be empty", nameof(metadata));
            
            if (string.IsNullOrEmpty(metadata.Hash))
                throw new ArgumentException("Hash cannot be empty", nameof(metadata));
        }

        private async Task ValidateUserExistsAsync(string userId)
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();

            var exists = await connection.ExecuteScalarAsync<bool>(
                "SELECT COUNT(1) FROM Users WHERE Id = @Id",
                new { Id = userId });

            if (!exists)
                throw new KeyNotFoundException($"User with ID {userId} not found");
        }

        private async Task<bool> IsEmailInUseAsync(string email, string? excludeUserId = null)
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();

            var query = "SELECT COUNT(1) FROM Users WHERE Email = @Email";
            var parameters = new { Email = email };

            if (!string.IsNullOrEmpty(excludeUserId))
            {
                query += " AND Id != @ExcludeId";
                parameters = new { Email = email, ExcludeId = excludeUserId };
            }

            var count = await connection.ExecuteScalarAsync<int>(query, parameters);
            return count > 0;
        }

        private async Task<bool> IsUsernameInUseAsync(string username, string? excludeUserId = null)
        {
            using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();

            var query = "SELECT COUNT(1) FROM Users WHERE Username = @Username";
            var parameters = new { Username = username };

            if (!string.IsNullOrEmpty(excludeUserId))
            {
                query += " AND Id != @ExcludeId";
                parameters = new { Username = username, ExcludeId = excludeUserId };
            }

            var count = await connection.ExecuteScalarAsync<int>(query, parameters);
            return count > 0;
        }

        // Βοηθητικές μέθοδοι μετατροπής τύπων
        private static string[] SplitTags(string? tags)
            => !string.IsNullOrEmpty(tags) 
                ? tags.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                : Array.Empty<string>();

        private static string JoinTags(IEnumerable<string>? tags)
            => tags != null 
                ? string.Join(",", tags.Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()))
                : string.Empty;

        private static string SerializeJson<T>(T obj)
            where T : class
            => obj != null ? System.Text.Json.JsonSerializer.Serialize(obj) : string.Empty;

        private static T? DeserializeJson<T>(string json)
            where T : class
            => !string.IsNullOrEmpty(json) 
                ? System.Text.Json.JsonSerializer.Deserialize<T>(json) 
                : null;

        private static string DateTimeToString(DateTime? dateTime)
            => dateTime?.ToString("O") ?? string.Empty;

        private static DateTime? StringToDateTime(string? value)
            => !string.IsNullOrEmpty(value) ? DateTime.Parse(value) : null;

        private static string BoolToInt(bool value) => value ? "1" : "0";
        
        private static bool IntToBool(object value)
        {
            if (value is long longValue)
                return longValue != 0;
            if (value is int intValue)
                return intValue != 0;
            if (int.TryParse(value?.ToString(), out int parsedValue))
                return parsedValue != 0;
            return false;
        }

        private static long GetSafeLong(object value)
        {
            if (value is long longValue)
                return longValue;
            if (value is int intValue)
                return intValue;
            if (long.TryParse(value?.ToString(), out long parsedValue))
                return parsedValue;
            return 0;
        }

        private static string SanitizeString(string? value)
            => value?.Trim() ?? string.Empty;

        private static string HashString(string value)
            => !string.IsNullOrEmpty(value) 
                ? Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(value)))
                : string.Empty;

        private static T SafeCast<T>(object? value, T defaultValue)
            where T : struct
        {
            if (value is T typedValue)
                return typedValue;
            
            try
            {
                return (T)Convert.ChangeType(value, typeof(T));
            }
            catch
            {
                return defaultValue;
            }
        }

        private static string GenerateId()
            => Guid.NewGuid().ToString("N");

        private static bool ValidateEmail(string? email)
            => !string.IsNullOrEmpty(email) && 
               Regex.IsMatch(email, 
                   @"^[^@\s]+@[^@\s]+\.[^@\s]+$", 
                   RegexOptions.IgnoreCase);

        private static bool ValidatePassword(string? password)
            => !string.IsNullOrEmpty(password) && password.Length >= 8;

        public async Task InitializeDatabaseAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                await CreateTablesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize database");
                throw;
            }
        }

        public async Task CreateTablesAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                // Create Users table
                await connection.ExecuteAsync(@"
                    CREATE TABLE IF NOT EXISTS Users (
                        Id TEXT PRIMARY KEY,
                        Username TEXT NOT NULL UNIQUE,
                        Email TEXT NOT NULL UNIQUE,
                        PasswordHash TEXT NOT NULL,
                        PasswordSalt TEXT NOT NULL,
                        Role TEXT NOT NULL,
                        EmailConfirmed INTEGER NOT NULL DEFAULT 0,
                        EmailConfirmationToken TEXT,
                        CreatedAt TEXT NOT NULL,
                        LastModified TEXT NOT NULL,
                        LastLoginAt TEXT,
                        IsActive INTEGER NOT NULL DEFAULT 1,
                        IsTwoFactorEnabled INTEGER NOT NULL DEFAULT 0,
                        TwoFactorKey TEXT,
                        RecoveryEmail TEXT,
                        FailedLoginAttempts INTEGER NOT NULL DEFAULT 0,
                        LockoutEnd TEXT
                    )");

                // Create PasswordEntries table
                await connection.ExecuteAsync(@"
                    CREATE TABLE IF NOT EXISTS PasswordEntries (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        UserId TEXT NOT NULL,
                        Title TEXT NOT NULL,
                        Username TEXT NOT NULL,
                        EncryptedPassword TEXT NOT NULL,
                        Website TEXT,
                        Category TEXT,
                        Tags TEXT,
                        Notes TEXT,
                        CreatedAt TEXT NOT NULL,
                        LastModified TEXT NOT NULL,
                        LastAccessed TEXT,
                        IsFavorite INTEGER NOT NULL DEFAULT 0,
                        ExpiryDays INTEGER,
                        PasswordStrength TEXT,
                        FOREIGN KEY(UserId) REFERENCES Users(Id)
                    )");

                // Create SecureNotes table
                await connection.ExecuteAsync(@"
                    CREATE TABLE IF NOT EXISTS SecureNotes (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        UserId TEXT NOT NULL,
                        Title TEXT NOT NULL,
                        Content TEXT NOT NULL,
                        Category TEXT,
                        Tags TEXT,
                        CreatedAt TEXT NOT NULL,
                        LastModified TEXT NOT NULL,
                        IsFavorite INTEGER NOT NULL DEFAULT 0,
                        FOREIGN KEY(UserId) REFERENCES Users(Id)
                    )");

                // Create SecureFiles table
                await connection.ExecuteAsync(@"
                    CREATE TABLE IF NOT EXISTS SecureFiles (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        UserId TEXT NOT NULL,
                        FileName TEXT NOT NULL,
                        FilePath TEXT NOT NULL,
                        FileType TEXT NOT NULL,
                        Size INTEGER NOT NULL,
                        Hash TEXT NOT NULL,
                        EncryptedPath TEXT NOT NULL,
                        CreatedAt TEXT NOT NULL,
                        LastModified TEXT NOT NULL,
                        LastAccessed TEXT,
                        Description TEXT,
                        Tags TEXT,
                        Category TEXT,
                        IsFavorite INTEGER NOT NULL DEFAULT 0,
                        Icon TEXT,
                        CustomFields TEXT,
                        Metadata TEXT,
                        FOREIGN KEY(UserId) REFERENCES Users(Id)
                    )");

                // Create UserSettings table
                await connection.ExecuteAsync(@"
                    CREATE TABLE IF NOT EXISTS UserSettings (
                        UserId TEXT PRIMARY KEY,
                        NotificationsEnabled INTEGER NOT NULL DEFAULT 1,
                        TwoFactorEnabled INTEGER NOT NULL DEFAULT 0,
                        Theme TEXT,
                        Language TEXT,
                        AutoLockTimeout INTEGER,
                        LastBackupAt TEXT,
                        LastModified TEXT NOT NULL,
                        FOREIGN KEY(UserId) REFERENCES Users(Id)
                    )");

                // Create BackupMetadata table
                await connection.ExecuteAsync(@"
                    CREATE TABLE IF NOT EXISTS BackupMetadata (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        UserId TEXT NOT NULL,
                        FileName TEXT NOT NULL,
                        FilePath TEXT NOT NULL,
                        EncryptedPath TEXT NOT NULL,
                        Status TEXT NOT NULL,
                        Hash TEXT NOT NULL,
                        Size INTEGER NOT NULL,
                        CreatedAt TEXT NOT NULL,
                        LastModified TEXT NOT NULL,
                        Description TEXT,
                        Error TEXT,
                        BackupPath TEXT NOT NULL,
                        IsAutomatic INTEGER NOT NULL DEFAULT 0,
                        CompletedAt TEXT,
                        ErrorMessage TEXT,
                        FOREIGN KEY(UserId) REFERENCES Users(Id)
                    )");

                // Create AuditLogs table
                await connection.ExecuteAsync(@"
                    CREATE TABLE IF NOT EXISTS AuditLogs (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        UserId TEXT NOT NULL,
                        EventType INTEGER NOT NULL,
                        Details TEXT NOT NULL,
                        AdditionalInfo TEXT,
                        IpAddress TEXT,
                        UserAgent TEXT,
                        IsSuccess INTEGER NOT NULL DEFAULT 1,
                        ErrorMessage TEXT,
                        Timestamp TEXT NOT NULL,
                        AffectedResource TEXT,
                        ResourceType TEXT,
                        Action TEXT,
                        ChangeDescription TEXT,
                        PreviousValue TEXT,
                        NewValue TEXT,
                        FOREIGN KEY(UserId) REFERENCES Users(Id)
                    )");

                // Create SecuritySettings table
                await connection.ExecuteAsync(@"
                    CREATE TABLE IF NOT EXISTS SecuritySettings (
                        Key TEXT PRIMARY KEY,
                        Value TEXT
                    )");

                // Create BackupCredentials table
                await connection.ExecuteAsync(@"
                    CREATE TABLE IF NOT EXISTS BackupCredentials (
                        UserId TEXT PRIMARY KEY,
                        BackupPath TEXT NOT NULL,
                        EncryptedPassword TEXT NOT NULL,
                        CreatedAt TEXT NOT NULL,
                        LastUsed TEXT NOT NULL
                    )");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create database tables");
                throw;
            }
        }

        public async Task<bool> BackupDatabaseAsync(string backupPath)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                // Create database backup
                using (var backupConnection = new SqliteConnection($"Data Source={backupPath}"))
                {
                    await backupConnection.OpenAsync();

                    // Copy data
                    using var command = connection.CreateCommand();
                    command.CommandText = "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL;";
                    using var reader = await command.ExecuteReaderAsync();

                    while (await reader.ReadAsync())
                    {
                        var sql = reader.GetString(0);
                        using var backupCommand = backupConnection.CreateCommand();
                        backupCommand.CommandText = sql;
                        await backupCommand.ExecuteNonQueryAsync();
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to backup database to {BackupPath}", backupPath);
                return false;
            }
        }

        public async Task<bool> RestoreDatabaseAsync(string backupPath)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                // Delete existing data
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "DROP TABLE IF EXISTS Users; DROP TABLE IF EXISTS PasswordEntries; /* etc for all tables */";
                    await command.ExecuteNonQueryAsync();
                }

                // Restore from backup
                using (var backupConnection = new SqliteConnection($"Data Source={backupPath}"))
                {
                    await backupConnection.OpenAsync();

                    // Copy data from backup
                    using var command = backupConnection.CreateCommand();
                    command.CommandText = "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL;";
                    using var reader = await command.ExecuteReaderAsync();

                    while (await reader.ReadAsync())
                    {
                        var sql = reader.GetString(0);
                        using var restoreCommand = connection.CreateCommand();
                        restoreCommand.CommandText = sql;
                        await restoreCommand.ExecuteNonQueryAsync();
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to restore database from {BackupPath}", backupPath);
                return false;
            }
        }

        public async Task<List<AuditLog>> GetAuditLogsAsync(string userId, int limit = 100)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var logs = await connection.QueryAsync<AuditLog>(@"
                    SELECT * FROM AuditLogs 
                    WHERE UserId = @UserId 
                    ORDER BY Timestamp DESC 
                    LIMIT @Limit",
                    new { UserId = userId, Limit = limit });

                return logs.AsList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get audit logs");
                throw;
            }
        }

        public async Task SaveAuditLogAsync(AuditLog log)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await connection.ExecuteAsync(@"
                    INSERT INTO AuditLogs (
                        UserId, EventType, Details, AdditionalInfo,
                        IpAddress, UserAgent, IsSuccess, ErrorMessage,
                        Timestamp, AffectedResource, ResourceType,
                        Action, ChangeDescription, PreviousValue,
                        NewValue
                    ) VALUES (
                        @UserId, @EventType, @Details, @AdditionalInfo,
                        @IpAddress, @UserAgent, @IsSuccess, @ErrorMessage,
                        @Timestamp, @AffectedResource, @ResourceType,
                        @Action, @ChangeDescription, @PreviousValue,
                        @NewValue
                    )", log);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log action");
                throw;
            }
        }

        public async Task<List<AuditLog>> GetAuditLogsAsync(string userId, DateTime startDate, DateTime endDate)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var logs = await connection.QueryAsync<AuditLog>(@"
                    SELECT * FROM AuditLogs 
                    WHERE UserId = @UserId 
                    AND Timestamp BETWEEN @StartDate AND @EndDate
                    ORDER BY Timestamp DESC",
                    new { UserId = userId, StartDate = startDate.ToString("O"), EndDate = endDate.ToString("O") });

                return logs.AsList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get audit logs by date range");
                throw;
            }
        }

        public async Task<List<AuditLog>> GetAuditLogsByTypeAsync(string userId, AuditEventType type)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var logs = await connection.QueryAsync<AuditLog>(
                    "SELECT * FROM AuditLogs WHERE UserId = @UserId AND EventType = @EventType",
                    new { UserId = userId, EventType = (int)type });

                return logs.AsList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get audit logs by type");
                throw;
            }
        }

        public async Task UpdateSecuritySettingAsync(string setting, string? value)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await connection.ExecuteAsync(@"
                    INSERT OR REPLACE INTO SecuritySettings (Key, Value)
                    VALUES (@Key, @Value)",
                    new { Key = setting, Value = value });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update security setting");
                throw;
            }
        }

        public async Task InitializeAsync(string encryptedVerification)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await connection.ExecuteAsync(@"
                    INSERT OR REPLACE INTO SecuritySettings (Key, Value)
                    VALUES ('VerificationData', @Value)",
                    new { Value = encryptedVerification });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize database with verification data");
                throw;
            }
        }

        public async Task InitializeNewUserAsync(string userId, string passwordHash, string salt)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await connection.ExecuteAsync(@"
                    INSERT INTO Users (
                        Id, Username, PasswordHash, PasswordSalt, CreatedAt, LastModified,
                        EmailConfirmed, IsActive, IsTwoFactorEnabled, FailedLoginAttempts
                    ) VALUES (
                        @UserId, @UserId, @Hash, @Salt, @CreatedAt, @LastModified,
                        @EmailConfirmed, @IsActive, @IsTwoFactorEnabled, @FailedLoginAttempts
                    )",
                    new
                    {
                        UserId = userId,
                        Hash = passwordHash,
                        Salt = salt,
                        CreatedAt = DateTimeToString(DateTime.UtcNow),
                        LastModified = DateTimeToString(DateTime.UtcNow),
                        EmailConfirmed = BoolToInt(false),
                        IsActive = BoolToInt(true),
                        IsTwoFactorEnabled = BoolToInt(false),
                        FailedLoginAttempts = 0
                    });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize new user");
                throw;
            }
        }

        public async Task<string> GetVerificationDataAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.QuerySingleOrDefaultAsync<string>(
                    "SELECT Value FROM SecuritySettings WHERE Key = 'VerificationData'");

                return result ?? string.Empty;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get verification data");
                throw;
            }
        }

        public async Task<bool> ValidateUserCredentialsAsync(string username, string passwordHash)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var storedHash = await connection.QuerySingleOrDefaultAsync<string>(
                    "SELECT PasswordHash FROM Users WHERE Username = @Username",
                    new { Username = username });

                return storedHash == passwordHash;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate user credentials");
                throw;
            }
        }

        public async Task<string> GetUserSaltAsync(string username)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var salt = await connection.QuerySingleOrDefaultAsync<string>(
                    "SELECT PasswordSalt FROM Users WHERE Username = @Username",
                    new { Username = username });

                return salt ?? throw new KeyNotFoundException("User not found");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user salt");
                throw;
            }
        }

        public async Task UpdatePasswordHashAsync(string username, string newPasswordHash)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await connection.ExecuteAsync(
                    "UPDATE Users SET PasswordHash = @Hash WHERE Username = @Username",
                    new { Hash = newPasswordHash, Username = username });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update password hash");
                throw;
            }
        }

        public async Task<string> RetrieveSecuritySettingAsync(string key)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var value = await connection.QuerySingleOrDefaultAsync<string>(
                    "SELECT Value FROM SecuritySettings WHERE Key = @Key",
                    new { Key = key });

                return value ?? string.Empty;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve security setting");
                throw;
            }
        }

        public async Task ReEncryptAllDataAsync(string userId, string newMasterKey)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();
                using var transaction = await connection.BeginTransactionAsync();

                try
                {
                    // Re-encrypt passwords
                    var passwords = await GetAllPasswordsAsync(userId);
                    foreach (var password in passwords)
                    {
                        // Re-encryption logic
                        password.EncryptedPassword = _encryptionService.ReEncrypt(
                            password.EncryptedPassword,
                            newMasterKey);
                        await SavePasswordAsync(password);
                    }

                    // Re-encrypt notes
                    var notes = await GetNotesAsync(userId);
                    foreach (var note in notes)
                    {
                        // Re-encryption logic
                        await SaveNoteAsync(note);
                    }

                    await transaction.CommitAsync();
                }
                catch
                {
                    await transaction.RollbackAsync();
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to re-encrypt all data");
                throw;
            }
        }

        // Password management implementations
        public async Task<List<PasswordEntry>> GetAllPasswordsAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID cannot be empty", nameof(userId));

            await ValidateUserExistsAsync(userId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var passwords = await connection.QueryAsync<PasswordEntry>(@"
                    SELECT * FROM PasswordEntries WHERE UserId = @UserId",
                    new { UserId = userId });

                var result = passwords.AsList();

                // Μετατροπή των τιμών από τη βάση δεδομένων
                foreach (var password in result)
                {
                    password.IsFavorite = IntToBool(password.IsFavorite);
                    password.CreatedAt = StringToDateTime(DateTimeToString(password.CreatedAt)) ?? DateTime.UtcNow;
                    password.LastModified = StringToDateTime(DateTimeToString(password.LastModified)) ?? DateTime.UtcNow;
                    password.LastAccessed = StringToDateTime(DateTimeToString(password.LastAccessed));
                    password.Tags = SplitTags(JoinTags(password.Tags));
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get all passwords");
                throw;
            }
        }

        public async Task<List<PasswordEntry>> GetPasswordsByCategoryAsync(string userId, string category)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID cannot be empty", nameof(userId));

            if (string.IsNullOrEmpty(category))
                throw new ArgumentException("Category cannot be empty", nameof(category));

            await ValidateUserExistsAsync(userId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var passwords = await connection.QueryAsync<PasswordEntry>(@"
                    SELECT * FROM PasswordEntries 
                    WHERE UserId = @UserId AND Category = @Category",
                    new { UserId = userId, Category = category });

                var result = passwords.AsList();

                // Μετατροπή των τιμών από τη βάση δεδομένων
                foreach (var password in result)
                {
                    password.IsFavorite = IntToBool(password.IsFavorite);
                    password.CreatedAt = StringToDateTime(password.CreatedAt?.ToString()) ?? DateTime.UtcNow;
                    password.LastModified = StringToDateTime(password.LastModified?.ToString()) ?? DateTime.UtcNow;
                    password.LastAccessed = StringToDateTime(password.LastAccessed?.ToString());
                    password.Tags = SplitTags(password.Tags?.ToString());
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get passwords by category");
                throw;
            }
        }

        public async Task<bool> SavePasswordAsync(PasswordEntry password)
        {
            ValidatePasswordEntry(password);
            await ValidateUserExistsAsync(password.UserId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                if (password.Id == 0)
                {
                    // Insert new password
                    var id = await connection.QuerySingleAsync<int>(@"
                        INSERT INTO PasswordEntries (
                            UserId, Title, Username, EncryptedPassword, Website,
                            Category, Tags, Notes, CreatedAt, LastModified,
                            LastAccessed, IsFavorite, ExpiryDays, PasswordStrength
                        ) VALUES (
                            @UserId, @Title, @Username, @EncryptedPassword, @Website,
                            @Category, @Tags, @Notes, @CreatedAt, @LastModified,
                            @LastAccessed, @IsFavorite, @ExpiryDays, @PasswordStrength
                        ) RETURNING Id;",
                        new
                        {
                            password.UserId,
                            password.Title,
                            password.Username,
                            password.EncryptedPassword,
                            password.Website,
                            password.Category,
                            Tags = JoinTags(password.Tags),
                            password.Notes,
                            CreatedAt = DateTimeToString(DateTime.UtcNow),
                            LastModified = DateTimeToString(DateTime.UtcNow),
                            LastAccessed = DateTimeToString(password.LastAccessed),
                            IsFavorite = BoolToInt(password.IsFavorite),
                            password.ExpiryDays,
                            password.PasswordStrength
                        });
                    return id > 0;
                }
                else
                {
                    // Update existing password
                    var result = await connection.ExecuteAsync(@"
                        UPDATE PasswordEntries SET
                            Title = @Title,
                            Username = @Username,
                            EncryptedPassword = @EncryptedPassword,
                            Website = @Website,
                            Category = @Category,
                            Tags = @Tags,
                            Notes = @Notes,
                            LastModified = @LastModified,
                            LastAccessed = @LastAccessed,
                            IsFavorite = @IsFavorite,
                            ExpiryDays = @ExpiryDays,
                            PasswordStrength = @PasswordStrength
                        WHERE Id = @Id AND UserId = @UserId",
                        new
                        {
                            password.Id,
                            password.UserId,
                            password.Title,
                            password.Username,
                            password.EncryptedPassword,
                            password.Website,
                            password.Category,
                            Tags = JoinTags(password.Tags),
                            password.Notes,
                            LastModified = DateTime.UtcNow,
                            LastAccessed = DateTime.UtcNow,
                            IsFavorite = BoolToInt(password.IsFavorite),
                            password.ExpiryDays,
                            password.PasswordStrength
                        });
                    return result > 0;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save password");
                throw;
            }
        }

        public async Task DeletePasswordAsync(int passwordId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await connection.ExecuteAsync(
                    "DELETE FROM PasswordEntries WHERE Id = @Id",
                    new { Id = passwordId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete password");
                throw;
            }
        }

        // Secure notes implementations
        public async Task<List<SecureNote>> GetNotesAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID cannot be empty", nameof(userId));

            await ValidateUserExistsAsync(userId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var notes = await connection.QueryAsync<SecureNote>(@"
                    SELECT * FROM SecureNotes WHERE UserId = @UserId",
                    new { UserId = userId });

                var result = notes.AsList();

                // Μετατροπή των τιμών από τη βάση δεδομένων
                foreach (var note in result)
                {
                    note.IsFavorite = IntToBool(note.IsFavorite);
                    note.IsEncrypted = IntToBool(note.IsEncrypted);
                    note.CreatedAt = StringToDateTime(DateTimeToString(note.CreatedAt)) ?? DateTime.UtcNow;
                    note.LastModified = StringToDateTime(DateTimeToString(note.LastModified)) ?? DateTime.UtcNow;
                    note.Tags = SplitTags(JoinTags(note.Tags));
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get notes");
                throw;
            }
        }

        public async Task<List<SecureNote>> GetAllNotesAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var notes = await connection.QueryAsync<SecureNote>(@"
                    SELECT * FROM SecureNotes");

                var result = notes.AsList();

                // Μετατροπή των τιμών από τη βάση δεδομένων
                foreach (var note in result)
                {
                    note.IsFavorite = IntToBool(note.IsFavorite);
                    note.CreatedAt = StringToDateTime(note.CreatedAt?.ToString()) ?? DateTime.UtcNow;
                    note.LastModified = StringToDateTime(note.LastModified?.ToString()) ?? DateTime.UtcNow;
                    note.Tags = SplitTags(note.Tags?.ToString());
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get all notes");
                throw;
            }
        }

        private void ValidateSecureNote(SecureNote note)
        {
            if (note == null)
                throw new ArgumentNullException(nameof(note));
            
            if (string.IsNullOrEmpty(note.UserId))
                throw new ArgumentException("User ID cannot be empty", nameof(note));
            
            if (string.IsNullOrEmpty(note.Title))
                throw new ArgumentException("Title cannot be empty", nameof(note));
            
            if (string.IsNullOrEmpty(note.Content))
                throw new ArgumentException("Content cannot be empty", nameof(note));
        }

        public async Task<bool> SaveNoteAsync(SecureNote note)
        {
            ValidateSecureNote(note);
            await ValidateUserExistsAsync(note.UserId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                if (note.Id == 0)
                {
                    // Insert new note
                    var id = await connection.QuerySingleAsync<int>(@"
                        INSERT INTO SecureNotes (
                            UserId, Title, Content, EncryptedContent, Category,
                            Tags, CreatedAt, LastModified, IsFavorite,
                            IsEncrypted, EncryptionKeyId
                        ) VALUES (
                            @UserId, @Title, @Content, @EncryptedContent, @Category,
                            @Tags, @CreatedAt, @LastModified, @IsFavorite,
                            @IsEncrypted, @EncryptionKeyId
                        ) RETURNING Id;",
                        new
                        {
                            note.UserId,
                            note.Title,
                            note.Content,
                            note.EncryptedContent,
                            note.Category,
                            Tags = JoinTags(note.Tags),
                            CreatedAt = DateTimeToString(DateTime.UtcNow),
                            LastModified = DateTimeToString(DateTime.UtcNow),
                            IsFavorite = BoolToInt(note.IsFavorite),
                            IsEncrypted = BoolToInt(note.IsEncrypted),
                            note.EncryptionKeyId
                        });
                    return id > 0;
                }
                else
                {
                    // Update existing note
                    var result = await connection.ExecuteAsync(@"
                        UPDATE SecureNotes SET
                            Title = @Title,
                            Content = @Content,
                            EncryptedContent = @EncryptedContent,
                            Category = @Category,
                            Tags = @Tags,
                            LastModified = @LastModified,
                            IsFavorite = @IsFavorite,
                            IsEncrypted = @IsEncrypted,
                            EncryptionKeyId = @EncryptionKeyId
                        WHERE Id = @Id AND UserId = @UserId",
                        new
                        {
                            note.Id,
                            note.UserId,
                            note.Title,
                            note.Content,
                            note.EncryptedContent,
                            note.Category,
                            Tags = JoinTags(note.Tags),
                            LastModified = DateTime.UtcNow,
                            IsFavorite = BoolToInt(note.IsFavorite),
                            IsEncrypted = BoolToInt(note.IsEncrypted),
                            note.EncryptionKeyId
                        });
                    return result > 0;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save note");
                throw;
            }
        }

        public async Task DeleteNoteAsync(int noteId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await connection.ExecuteAsync(
                    "DELETE FROM SecureNotes WHERE Id = @Id",
                    new { Id = noteId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete note");
                throw;
            }
        }

        // Secure files implementations
        public async Task<List<SecureFile>> GetSecureFilesAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID cannot be empty", nameof(userId));

            await ValidateUserExistsAsync(userId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var files = await connection.QueryAsync<SecureFile>(@"
                    SELECT * FROM SecureFiles WHERE UserId = @UserId",
                    new { UserId = userId });

                var result = files.AsList();

                // Μετατροπή των τιμών από τη βάση δεδομένων
                foreach (var file in result)
                {
                    file.IsEncrypted = IntToBool(file.IsEncrypted);
                    file.IsShared = IntToBool(file.IsShared);
                    file.IsFavorite = IntToBool(file.IsFavorite);
                    file.CreatedAt = StringToDateTime(DateTimeToString(file.CreatedAt)) ?? DateTime.UtcNow;
                    file.LastModified = StringToDateTime(DateTimeToString(file.LastModified)) ?? DateTime.UtcNow;
                    file.LastAccessed = StringToDateTime(DateTimeToString(file.LastAccessed));
                    file.ExpiresAt = StringToDateTime(DateTimeToString(file.ExpiresAt));
                    file.Size = GetSafeLong(file.Size);
                    file.Tags = SplitTags(JoinTags(file.Tags));
                    file.SharedWith = SplitTags(JoinTags(file.SharedWith));
                    file.CustomFields = DeserializeJson<Dictionary<string, string>>(SerializeJson(file.CustomFields)) ?? new Dictionary<string, string>();
                    file.Metadata = DeserializeJson<Dictionary<string, string>>(SerializeJson(file.Metadata)) ?? new Dictionary<string, string>();
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get secure files");
                throw;
            }
        }

        public async Task<SecureFile> GetSecureFileAsync(int fileId)
        {
            if (fileId <= 0)
                throw new ArgumentException("Invalid file ID", nameof(fileId));

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var file = await connection.QuerySingleOrDefaultAsync<SecureFile>(@"
                    SELECT * FROM SecureFiles WHERE Id = @Id",
                    new { Id = fileId });

                if (file == null)
                    throw new KeyNotFoundException($"Secure file with ID {fileId} not found");

                // Μετατροπή των τιμών από τη βάση δεδομένων
                file.IsEncrypted = IntToBool(file.IsEncrypted);
                file.IsShared = IntToBool(file.IsShared);
                file.IsFavorite = IntToBool(file.IsFavorite);
                file.CreatedAt = StringToDateTime(file.CreatedAt?.ToString()) ?? DateTime.UtcNow;
                file.LastModified = StringToDateTime(file.LastModified?.ToString()) ?? DateTime.UtcNow;
                file.LastAccessed = StringToDateTime(file.LastAccessed?.ToString());
                file.ExpiresAt = StringToDateTime(file.ExpiresAt?.ToString());
                file.Size = GetSafeLong(file.Size);
                file.Tags = SplitTags(file.Tags?.ToString());
                file.SharedWith = SplitTags(file.SharedWith?.ToString());
                file.CustomFields = DeserializeJson<Dictionary<string, string>>(file.CustomFields?.ToString());
                file.Metadata = DeserializeJson<Dictionary<string, string>>(file.Metadata?.ToString());

                return file;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get secure file");
                throw;
            }
        }

        public async Task<bool> SaveSecureFileAsync(SecureFile file)
        {
            ValidateSecureFile(file);
            await ValidateUserExistsAsync(file.UserId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                if (file.Id == 0)
                {
                    // Insert new file
                    var id = await connection.QuerySingleAsync<int>(@"
                        INSERT INTO SecureFiles (
                            UserId, FileName, FilePath, FileType, Size,
                            Hash, EncryptedPath, CreatedAt, LastModified,
                            LastAccessed, Description, Tags, Category,
                            IsFavorite, Icon, CustomFields, Metadata,
                            IsEncrypted, ContentType, IsShared, SharedWith,
                            ExpiresAt, Version, Checksum, MimeType, ThumbnailPath
                        ) VALUES (
                            @UserId, @FileName, @FilePath, @FileType, @Size,
                            @Hash, @EncryptedPath, @CreatedAt, @LastModified,
                            @LastAccessed, @Description, @Tags, @Category,
                            @IsFavorite, @Icon, @CustomFields, @Metadata,
                            @IsEncrypted, @ContentType, @IsShared, @SharedWith,
                            @ExpiresAt, @Version, @Checksum, @MimeType, @ThumbnailPath
                        ) RETURNING Id;",
                        new
                        {
                            file.UserId,
                            file.FileName,
                            file.FilePath,
                            file.FileType,
                            file.Size,
                            file.Hash,
                            file.EncryptedPath,
                            CreatedAt = DateTimeToString(DateTime.UtcNow),
                            LastModified = DateTimeToString(DateTime.UtcNow),
                            LastAccessed = DateTimeToString(file.LastAccessed),
                            file.Description,
                            Tags = JoinTags(file.Tags),
                            file.Category,
                            IsFavorite = BoolToInt(file.IsFavorite),
                            file.Icon,
                            CustomFields = SerializeJson(file.CustomFields),
                            Metadata = SerializeJson(file.Metadata),
                            IsEncrypted = BoolToInt(file.IsEncrypted),
                            file.ContentType,
                            IsShared = BoolToInt(file.IsShared),
                            SharedWith = JoinTags(file.SharedWith),
                            ExpiresAt = DateTimeToString(file.ExpiresAt),
                            file.Version,
                            file.Checksum,
                            file.MimeType,
                            file.ThumbnailPath
                        });
                    return id > 0;
                }
                else
                {
                    // Update existing file
                    var result = await connection.ExecuteAsync(@"
                        UPDATE SecureFiles SET
                            FileName = @FileName,
                            FilePath = @FilePath,
                            FileType = @FileType,
                            Size = @Size,
                            Hash = @Hash,
                            EncryptedPath = @EncryptedPath,
                            LastModified = @LastModified,
                            LastAccessed = @LastAccessed,
                            Description = @Description,
                            Tags = @Tags,
                            Category = @Category,
                            IsFavorite = @IsFavorite,
                            Icon = @Icon,
                            CustomFields = @CustomFields,
                            Metadata = @Metadata,
                            IsEncrypted = @IsEncrypted,
                            ContentType = @ContentType,
                            IsShared = @IsShared,
                            SharedWith = @SharedWith,
                            ExpiresAt = @ExpiresAt,
                            Version = @Version,
                            Checksum = @Checksum,
                            MimeType = @MimeType,
                            ThumbnailPath = @ThumbnailPath
                        WHERE Id = @Id AND UserId = @UserId",
                        new
                        {
                            file.Id,
                            file.UserId,
                            file.FileName,
                            file.FilePath,
                            file.FileType,
                            file.Size,
                            file.Hash,
                            file.EncryptedPath,
                            LastModified = DateTime.UtcNow,
                            LastAccessed = DateTime.UtcNow,
                            file.Description,
                            Tags = JoinTags(file.Tags),
                            file.Category,
                            IsFavorite = BoolToInt(file.IsFavorite),
                            file.Icon,
                            CustomFields = SerializeJson(file.CustomFields),
                            Metadata = SerializeJson(file.Metadata),
                            IsEncrypted = BoolToInt(file.IsEncrypted),
                            file.ContentType,
                            IsShared = BoolToInt(file.IsShared),
                            SharedWith = JoinTags(file.SharedWith),
                            ExpiresAt = DateTimeToString(file.ExpiresAt),
                            file.Version,
                            file.Checksum,
                            file.MimeType,
                            file.ThumbnailPath
                        });
                    return result > 0;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save secure file");
                throw;
            }
        }

        public async Task DeleteSecureFileAsync(int fileId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await connection.ExecuteAsync(
                    "DELETE FROM SecureFiles WHERE Id = @Id",
                    new { Id = fileId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete secure file");
                throw;
            }
        }

        // Backup management implementations
        public async Task<List<BackupMetadata>> GetBackupHistoryAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID cannot be empty", nameof(userId));

            await ValidateUserExistsAsync(userId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var backups = await connection.QueryAsync<BackupMetadata>(@"
                    SELECT * FROM BackupMetadata 
                    WHERE UserId = @UserId 
                    ORDER BY CreatedAt DESC",
                    new { UserId = userId });

                var result = backups.AsList();

                // Μετατροπή των τιμών από τη βάση δεδομένων
                foreach (var backup in result)
                {
                    backup.IsAutomatic = IntToBool(backup.IsAutomatic);
                    backup.CreatedAt = StringToDateTime(backup.CreatedAt?.ToString()) ?? DateTime.UtcNow;
                    backup.LastModified = StringToDateTime(backup.LastModified?.ToString()) ?? DateTime.UtcNow;
                    backup.CompletedAt = StringToDateTime(backup.CompletedAt?.ToString());
                    backup.Size = GetSafeLong(backup.Size);
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get backup history");
                throw;
            }
        }

        public async Task<bool> DeleteBackupMetadataAsync(int backupId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.ExecuteAsync(
                    "DELETE FROM BackupMetadata WHERE Id = @Id",
                    new { Id = backupId });

                return result > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete backup metadata");
                throw;
            }
        }

        public async Task<UserSettings> GetUserSettingsAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID cannot be empty", nameof(userId));

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var settings = await connection.QuerySingleOrDefaultAsync<UserSettings>(@"
                    SELECT * FROM UserSettings WHERE UserId = @UserId",
                    new { UserId = userId });

                if (settings == null)
                {
                    // Δημιουργία προεπιλεγμένων ρυθμίσεων
                    settings = new UserSettings
                    {
                        UserId = userId,
                        AutoLockEnabled = true,
                        AutoLockTimeout = 5, // 5 λεπτά προεπιλογή
                        NotificationsEnabled = true,
                        Theme = "system",
                        Language = "el-GR",
                        PasswordGeneratorSettings = true,
                        DefaultPasswordLength = 16,
                        UseSpecialCharacters = true,
                        UseNumbers = true,
                        UseUppercase = true
                    };

                    // Αποθήκευση των προεπιλεγμένων ρυθμίσεων
                    await SaveUserSettingsAsync(userId, settings);
                }
                else
                {
                    // Μετατροπή των τιμών από τη βάση δεδομένων
                    settings.AutoLockEnabled = IntToBool(settings.AutoLockEnabled);
                    settings.NotificationsEnabled = IntToBool(settings.NotificationsEnabled);
                    settings.PasswordGeneratorSettings = IntToBool(settings.PasswordGeneratorSettings);
                    settings.UseSpecialCharacters = IntToBool(settings.UseSpecialCharacters);
                    settings.UseNumbers = IntToBool(settings.UseNumbers);
                    settings.UseUppercase = IntToBool(settings.UseUppercase);
                }

                return settings;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user settings");
                throw;
            }
        }

        public async Task<bool> SaveUserSettingsAsync(string userId, UserSettings settings)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID cannot be empty", nameof(userId));

            if (settings == null)
                throw new ArgumentNullException(nameof(settings));

            await ValidateUserExistsAsync(userId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.ExecuteAsync(@"
                    INSERT INTO UserSettings (
                        UserId, AutoLockEnabled, AutoLockTimeout, NotificationsEnabled,
                        Theme, Language, PasswordGeneratorSettings, DefaultPasswordLength,
                        UseSpecialCharacters, UseNumbers, UseUppercase, LastModified
                    ) VALUES (
                        @UserId, @AutoLockEnabled, @AutoLockTimeout, @NotificationsEnabled,
                        @Theme, @Language, @PasswordGeneratorSettings, @DefaultPasswordLength,
                        @UseSpecialCharacters, @UseNumbers, @UseUppercase, @LastModified
                    )",
                    new
                    {
                        UserId = userId,
                        AutoLockEnabled = BoolToInt(settings.AutoLockEnabled),
                        settings.AutoLockTimeout,
                        NotificationsEnabled = BoolToInt(settings.NotificationsEnabled),
                        Theme = SanitizeString(settings.Theme),
                        Language = SanitizeString(settings.Language),
                        PasswordGeneratorSettings = BoolToInt(settings.PasswordGeneratorSettings),
                        settings.DefaultPasswordLength,
                        UseSpecialCharacters = BoolToInt(settings.UseSpecialCharacters),
                        UseNumbers = BoolToInt(settings.UseNumbers),
                        UseUppercase = BoolToInt(settings.UseUppercase),
                        LastModified = DateTime.UtcNow
                    });

                return result > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save user settings");
                throw;
            }
        }

        public async Task<bool> UpdateUserSettingsAsync(string userId, UserSettings settings)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID cannot be empty", nameof(userId));

            if (settings == null)
                throw new ArgumentNullException(nameof(settings));

            await ValidateUserExistsAsync(userId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.ExecuteAsync(@"
                    UPDATE UserSettings SET
                        AutoLockEnabled = @AutoLockEnabled,
                        AutoLockTimeout = @AutoLockTimeout,
                        NotificationsEnabled = @NotificationsEnabled,
                        Theme = @Theme,
                        Language = @Language,
                        PasswordGeneratorSettings = @PasswordGeneratorSettings,
                        DefaultPasswordLength = @DefaultPasswordLength,
                        UseSpecialCharacters = @UseSpecialCharacters,
                        UseNumbers = @UseNumbers,
                        UseUppercase = @UseUppercase,
                        LastModified = @LastModified
                    WHERE UserId = @UserId",
                    new
                    {
                        UserId = userId,
                        AutoLockEnabled = BoolToInt(settings.AutoLockEnabled),
                        settings.AutoLockTimeout,
                        NotificationsEnabled = BoolToInt(settings.NotificationsEnabled),
                        Theme = SanitizeString(settings.Theme),
                        Language = SanitizeString(settings.Language),
                        PasswordGeneratorSettings = BoolToInt(settings.PasswordGeneratorSettings),
                        settings.DefaultPasswordLength,
                        UseSpecialCharacters = BoolToInt(settings.UseSpecialCharacters),
                        UseNumbers = BoolToInt(settings.UseNumbers),
                        UseUppercase = BoolToInt(settings.UseUppercase),
                        LastModified = DateTime.UtcNow
                    });

                return result > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update user settings");
                throw;
            }
        }

        public async Task<bool> ClearAuditLogsAsync(string userId, DateTime before)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.ExecuteAsync(
                    "DELETE FROM AuditLogs WHERE UserId = @UserId AND Timestamp < @Before",
                    new { UserId = userId, Before = DateTimeToString(before) });

                return result > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear audit logs");
                throw;
            }
        }

        public async Task<bool> SaveBackupMetadataAsync(BackupMetadata metadata)
        {
            ValidateBackupMetadata(metadata);
            await ValidateUserExistsAsync(metadata.UserId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.ExecuteAsync(@"
                    INSERT INTO BackupMetadata (
                        UserId, FileName, FilePath, EncryptedPath, Status, Hash, Size,
                        CreatedAt, LastModified, Description, Error, BackupPath, IsAutomatic,
                        IsEncrypted, CompletedAt, ErrorMessage
                    ) VALUES (
                        @UserId, @FileName, @FilePath, @EncryptedPath, @Status, @Hash, @Size,
                        @CreatedAt, @LastModified, @Description, @Error, @BackupPath, @IsAutomatic,
                        @IsEncrypted, @CompletedAt, @ErrorMessage
                    )",
                    new
                    {
                        metadata.UserId,
                        metadata.FileName,
                        metadata.FilePath,
                        metadata.EncryptedPath,
                        metadata.Status,
                        metadata.Hash,
                        metadata.Size,
                        CreatedAt = DateTimeToString(metadata.CreatedAt),
                        LastModified = DateTimeToString(metadata.LastModified),
                        Description = SanitizeString(metadata.Description),
                        Error = SanitizeString(metadata.Error),
                        metadata.BackupPath,
                        IsAutomatic = BoolToInt(metadata.IsAutomatic),
                        IsEncrypted = BoolToInt(metadata.IsEncrypted),
                        CompletedAt = DateTimeToString(metadata.CompletedAt),
                        ErrorMessage = SanitizeString(metadata.ErrorMessage)
                    });

                return result > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save backup metadata");
                return false;
            }
        }

        public async Task UpdateVerificationDataAsync(string data)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await connection.ExecuteAsync(@"
                    INSERT OR REPLACE INTO SecuritySettings (Key, Value)
                    VALUES ('VerificationData', @Value)",
                    new { Value = data });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update verification data");
                throw;
            }
        }

        public async Task<BackupConfiguration> GetBackupConfigurationAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var config = await connection.QuerySingleOrDefaultAsync<BackupConfiguration>(@"
                    SELECT * FROM BackupConfiguration LIMIT 1");

                if (config == null)
                {
                    // Δημιουργία προεπιλεγμένης διαμόρφωσης
                    config = new BackupConfiguration
                    {
                        BackupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "SecureVault", "Backups"),
                        AutoBackupEnabled = true,
                        BackupFrequencyDays = 7,
                        RetentionPeriodDays = 30,
                        EncryptBackups = true,
                        MaxBackupCount = 10,
                        MaxBackupSize = 1024 * 1024 * 100, // 100 MB
                        BackupFormat = "zip",
                        CompressBackups = true
                    };

                    // Αποθήκευση της προεπιλεγμένης διαμόρφωσης
                    await UpdateBackupConfigurationAsync(config);
                }
                else
                {
                    // Μετατροπή των τιμών από τη βάση δεδομένων
                    config.AutoBackupEnabled = IntToBool(config.AutoBackupEnabled);
                    config.EncryptBackups = IntToBool(config.EncryptBackups);
                    config.CompressBackups = IntToBool(config.CompressBackups);
                    config.MaxBackupSize = GetSafeLong(config.MaxBackupSize);
                    config.BackupPath = SanitizeString(config.BackupPath);
                    config.BackupFormat = SanitizeString(config.BackupFormat);
                }

                return config;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get backup configuration");
                throw;
            }
        }

        public async Task UpdateBackupConfigurationAsync(BackupConfiguration config)
        {
            if (config == null)
                throw new ArgumentNullException(nameof(config));

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await connection.ExecuteAsync(@"
                    INSERT OR REPLACE INTO BackupConfiguration (
                        BackupPath, AutoBackupEnabled, BackupFrequencyDays,
                        RetentionPeriodDays, EncryptBackups, MaxBackupCount,
                        MaxBackupSize, BackupFormat, CompressBackups, LastBackupTime
                    ) VALUES (
                        @BackupPath, @AutoBackupEnabled, @BackupFrequencyDays,
                        @RetentionPeriodDays, @EncryptBackups, @MaxBackupCount,
                        @MaxBackupSize, @BackupFormat, @CompressBackups, @LastBackupTime
                    )",
                    new
                    {
                        BackupPath = SanitizeString(config.BackupPath),
                        AutoBackupEnabled = BoolToInt(config.AutoBackupEnabled),
                        config.BackupFrequencyDays,
                        config.RetentionPeriodDays,
                        EncryptBackups = BoolToInt(config.EncryptBackups),
                        config.MaxBackupCount,
                        config.MaxBackupSize,
                        BackupFormat = SanitizeString(config.BackupFormat),
                        CompressBackups = BoolToInt(config.CompressBackups),
                        LastBackupTime = DateTimeToString(config.LastBackupTime)
                    });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update backup configuration");
                throw;
            }
        }

        public async Task<User> GetUserByIdAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID cannot be empty", nameof(userId));

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var user = await connection.QuerySingleOrDefaultAsync<User>(@"
                    SELECT * FROM Users WHERE Id = @Id",
                    new { Id = userId });

                if (user == null)
                    throw new KeyNotFoundException($"User with ID {userId} not found");

                // Μετατροπή των τιμών από τη βάση δεδομένων
                user.EmailConfirmed = IntToBool(user.EmailConfirmed);
                user.IsActive = IntToBool(user.IsActive);
                user.IsTwoFactorEnabled = IntToBool(user.IsTwoFactorEnabled);
                user.LastLoginAt = StringToDateTime(user.LastLoginAt?.ToString());
                user.LockoutEnd = StringToDateTime(user.LockoutEnd?.ToString());

                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user by ID");
                throw;
            }
        }

        public async Task<User> GetUserByUsernameAsync(string username)
        {
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Username cannot be empty", nameof(username));

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var user = await connection.QuerySingleOrDefaultAsync<User>(@"
                    SELECT * FROM Users WHERE Username = @Username",
                    new { Username = username });

                if (user == null)
                    throw new KeyNotFoundException($"User with username {username} not found");

                // Μετατροπή των τιμών από τη βάση δεδομένων
                user.EmailConfirmed = IntToBool(user.EmailConfirmed);
                user.IsActive = IntToBool(user.IsActive);
                user.IsTwoFactorEnabled = IntToBool(user.IsTwoFactorEnabled);
                user.LastLoginAt = StringToDateTime(user.LastLoginAt?.ToString());
                user.LockoutEnd = StringToDateTime(user.LockoutEnd?.ToString());

                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user by username");
                throw;
            }
        }

        public async Task<User> GetUserByEmailAsync(string email)
        {
            if (!ValidateEmail(email))
                throw new ArgumentException("Invalid email format", nameof(email));

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var user = await connection.QuerySingleOrDefaultAsync<User>(@"
                    SELECT * FROM Users WHERE Email = @Email",
                    new { Email = email });

                if (user == null)
                    throw new KeyNotFoundException($"User with email {email} not found");

                // Μετατροπή των τιμών από τη βάση δεδομένων
                user.EmailConfirmed = IntToBool(user.EmailConfirmed);
                user.IsActive = IntToBool(user.IsActive);
                user.IsTwoFactorEnabled = IntToBool(user.IsTwoFactorEnabled);
                user.LastLoginAt = StringToDateTime(user.LastLoginAt?.ToString());
                user.LockoutEnd = StringToDateTime(user.LockoutEnd?.ToString());

                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user by email");
                throw;
            }
        }

        public async Task<bool> CreateUserAsync(User user)
        {
            ValidateUser(user);

            if (await IsEmailInUseAsync(user.Email))
                throw new InvalidOperationException("Email is already in use");

            if (await IsUsernameInUseAsync(user.Username))
                throw new InvalidOperationException("Username is already in use");

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.ExecuteAsync(@"
                    INSERT INTO Users (
                        Id, Username, Email, PasswordHash, PasswordSalt, Role,
                        EmailConfirmed, EmailConfirmationToken, CreatedAt,
                        LastModified, LastLoginAt, IsActive, IsTwoFactorEnabled,
                        TwoFactorKey, RecoveryEmail, FailedLoginAttempts, LockoutEnd
                    ) VALUES (
                        @Id, @Username, @Email, @PasswordHash, @PasswordSalt, @Role,
                        @EmailConfirmed, @EmailConfirmationToken, @CreatedAt,
                        @LastModified, @LastLoginAt, @IsActive, @IsTwoFactorEnabled,
                        @TwoFactorKey, @RecoveryEmail, @FailedLoginAttempts, @LockoutEnd
                    )", new
                    {
                        user.Id,
                        user.Username,
                        user.Email,
                        user.PasswordHash,
                        user.PasswordSalt,
                        user.Role,
                        EmailConfirmed = BoolToInt(user.EmailConfirmed),
                        user.EmailConfirmationToken,
                        CreatedAt = DateTimeToString(DateTime.UtcNow),
                        LastModified = DateTimeToString(DateTime.UtcNow),
                        LastLoginAt = DateTimeToString(user.LastLoginAt),
                        IsActive = BoolToInt(user.IsActive),
                        IsTwoFactorEnabled = BoolToInt(user.IsTwoFactorEnabled),
                        user.TwoFactorKey,
                        user.RecoveryEmail,
                        user.FailedLoginAttempts,
                        LockoutEnd = DateTimeToString(user.LockoutEnd)
                    });

                return result > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create user");
                throw;
            }
        }

        public async Task<bool> UpdateUserAsync(User user)
        {
            ValidateUser(user);

            // Έλεγχος για διπλότυπα email/username
            if (await IsEmailInUseAsync(user.Email, user.Id))
                throw new InvalidOperationException("Email is already in use by another user");

            if (await IsUsernameInUseAsync(user.Username, user.Id))
                throw new InvalidOperationException("Username is already in use by another user");

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.ExecuteAsync(@"
                    UPDATE Users SET
                        Username = @Username,
                        Email = @Email,
                        PasswordHash = @PasswordHash,
                        PasswordSalt = @PasswordSalt,
                        Role = @Role,
                        EmailConfirmed = @EmailConfirmed,
                        EmailConfirmationToken = @EmailConfirmationToken,
                        LastModified = @LastModified,
                        LastLoginAt = @LastLoginAt,
                        IsActive = @IsActive,
                        IsTwoFactorEnabled = @IsTwoFactorEnabled,
                        TwoFactorKey = @TwoFactorKey,
                        RecoveryEmail = @RecoveryEmail,
                        FailedLoginAttempts = @FailedLoginAttempts,
                        LockoutEnd = @LockoutEnd
                    WHERE Id = @Id",
                    new
                    {
                        user.Id,
                        user.Username,
                        user.Email,
                        user.PasswordHash,
                        user.PasswordSalt,
                        user.Role,
                        EmailConfirmed = BoolToInt(user.EmailConfirmed),
                        user.EmailConfirmationToken,
                        LastModified = DateTime.UtcNow,
                        LastLoginAt = DateTime.UtcNow,
                        IsActive = BoolToInt(user.IsActive),
                        IsTwoFactorEnabled = BoolToInt(user.IsTwoFactorEnabled),
                        user.TwoFactorKey,
                        user.RecoveryEmail,
                        user.FailedLoginAttempts,
                        LockoutEnd = DateTime.UtcNow
                    });

                return result > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update user");
                throw;
            }
        }

        public async Task<bool> DeleteUserAsync(string userId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.ExecuteAsync(
                    "DELETE FROM Users WHERE Id = @Id",
                    new { Id = userId });

                return result > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete user");
                throw;
            }
        }

        public async Task<BackupMetadata> GetBackupMetadataByIdAsync(int id)
        {
            if (id <= 0)
                throw new ArgumentException("Invalid backup metadata ID", nameof(id));

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var metadata = await connection.QuerySingleOrDefaultAsync<BackupMetadata>(@"
                    SELECT * FROM BackupMetadata WHERE Id = @Id",
                    new { Id = id });

                if (metadata == null)
                    throw new KeyNotFoundException($"Backup metadata with ID {id} not found");

                // Μετατροπή των τιμών από τη βάση δεδομένων
                metadata.IsAutomatic = IntToBool(metadata.IsAutomatic);
                metadata.CreatedAt = StringToDateTime(metadata.CreatedAt?.ToString()) ?? DateTime.UtcNow;
                metadata.LastModified = StringToDateTime(metadata.LastModified?.ToString()) ?? DateTime.UtcNow;
                metadata.CompletedAt = StringToDateTime(metadata.CompletedAt?.ToString());
                metadata.Size = GetSafeLong(metadata.Size);

                return metadata;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get backup metadata by ID");
                throw;
            }
        }

        public async Task<bool> UpdateBackupMetadataAsync(BackupMetadata metadata)
        {
            ValidateBackupMetadata(metadata);
            await ValidateUserExistsAsync(metadata.UserId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.ExecuteAsync(@"
                    UPDATE BackupMetadata SET
                        UserId = @UserId,
                        FileName = @FileName,
                        FilePath = @FilePath,
                        EncryptedPath = @EncryptedPath,
                        Status = @Status,
                        Hash = @Hash,
                        Size = @Size,
                        LastModified = @LastModified,
                        Description = @Description,
                        Error = @Error,
                        BackupPath = @BackupPath,
                        IsAutomatic = @IsAutomatic,
                        IsEncrypted = @IsEncrypted,
                        CompletedAt = @CompletedAt,
                        ErrorMessage = @ErrorMessage
                    WHERE Id = @Id",
                    new
                    {
                        metadata.Id,
                        metadata.UserId,
                        metadata.FileName,
                        metadata.FilePath,
                        metadata.EncryptedPath,
                        metadata.Status,
                        metadata.Hash,
                        metadata.Size,
                        LastModified = DateTime.UtcNow,
                        Description = SanitizeString(metadata.Description),
                        Error = SanitizeString(metadata.Error),
                        metadata.BackupPath,
                        IsAutomatic = BoolToInt(metadata.IsAutomatic),
                        IsEncrypted = BoolToInt(metadata.IsEncrypted),
                        CompletedAt = DateTimeToString(metadata.CompletedAt),
                        ErrorMessage = SanitizeString(metadata.ErrorMessage)
                    });

                return result > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update backup metadata");
                throw;
            }
        }

        public async Task UpdateLastBackupTimeAsync(DateTime lastBackupTime)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                await connection.ExecuteAsync(@"
                    INSERT OR REPLACE INTO SecuritySettings (Key, Value)
                    VALUES ('LastBackupTime', @Value)",
                    new { Value = lastBackupTime.ToString("O") });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update last backup time");
                throw;
            }
        }

        public async Task<bool> SaveBackupCredentialAsync(BackupCredential credential)
        {
            if (credential == null)
                throw new ArgumentNullException(nameof(credential));

            if (string.IsNullOrEmpty(credential.UserId))
                throw new ArgumentException("User ID cannot be empty", nameof(credential));

            if (string.IsNullOrEmpty(credential.BackupPath))
                throw new ArgumentException("Backup path cannot be empty", nameof(credential));

            if (string.IsNullOrEmpty(credential.EncryptedPassword))
                throw new ArgumentException("Encrypted password cannot be empty", nameof(credential));

            await ValidateUserExistsAsync(credential.UserId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.ExecuteAsync(@"
                    INSERT INTO BackupCredentials (
                        UserId, BackupPath, EncryptedPassword, CreatedAt, LastUsed
                    ) VALUES (
                        @UserId, @BackupPath, @EncryptedPassword, @CreatedAt, @LastUsed
                    )",
                    new
                    {
                        credential.UserId,
                        BackupPath = SanitizeString(credential.BackupPath),
                        credential.EncryptedPassword,
                        CreatedAt = DateTime.UtcNow,
                        LastUsed = DateTime.UtcNow
                    });

                return result > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save backup credential");
                throw;
            }
        }

        public async Task<BackupCredential> GetBackupCredentialAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID cannot be empty", nameof(userId));

            await ValidateUserExistsAsync(userId);

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var credential = await connection.QuerySingleOrDefaultAsync<BackupCredential>(@"
                    SELECT * FROM BackupCredentials WHERE UserId = @UserId",
                    new { UserId = userId });

                if (credential == null)
                    throw new KeyNotFoundException($"Backup credential for user {userId} not found");

                // Μετατροπή των τιμών από τη βάση δεδομένων
                credential.CreatedAt = StringToDateTime(credential.CreatedAt?.ToString()) ?? DateTime.UtcNow;
                credential.LastUsed = StringToDateTime(credential.LastUsed?.ToString()) ?? DateTime.UtcNow;
                credential.BackupPath = SanitizeString(credential.BackupPath);

                return credential;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get backup credential");
                throw;
            }
        }

        public async Task<bool> DeleteBackupCredentialAsync(string userId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.ExecuteAsync(
                    "DELETE FROM BackupCredentials WHERE UserId = @UserId",
                    new { UserId = userId });

                return result > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete backup credential");
                throw;
            }
        }

        public async Task<bool> UpdatePasswordAsync(string userId, int passwordId, PasswordEntry password)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var result = await connection.ExecuteAsync(@"
                    UPDATE PasswordEntries SET
                        Title = @Title,
                        Username = @Username,
                        EncryptedPassword = @EncryptedPassword,
                        Website = @Website,
                        Category = @Category,
                        Tags = @Tags,
                        Notes = @Notes,
                        LastModified = @LastModified,
                        LastAccessed = @LastAccessed,
                        IsFavorite = @IsFavorite,
                        ExpiryDays = @ExpiryDays,
                        PasswordStrength = @PasswordStrength
                    WHERE Id = @Id AND UserId = @UserId",
                    new
                    {
                        password.Title,
                        password.Username,
                        password.EncryptedPassword,
                        password.Website,
                        password.Category,
                        Tags = JoinTags(password.Tags),
                        password.Notes,
                        LastModified = DateTime.UtcNow,
                        LastAccessed = DateTime.UtcNow,
                        IsFavorite = BoolToInt(password.IsFavorite),
                        password.ExpiryDays,
                        password.PasswordStrength,
                        Id = passwordId,
                        UserId = userId
                    });

                return result > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update password");
                throw;
            }
        }

        public async Task LogEventAsync(string userId, AuditEventType eventType, string description)
        {
            var log = new AuditLog
            {
                UserId = userId,
                EventType = eventType,
                Details = description,
                Timestamp = DateTime.UtcNow,
                IsSuccess = true
            };

            await SaveAuditLogAsync(log);
            _logger.LogInformation($"Audit event logged: {eventType} for user {userId}");
        }

        public async Task LogActionAsync(string userId, AuditEventType eventType, string action, string details = null)
        {
            var log = new AuditLog
            {
                UserId = userId,
                EventType = eventType,
                Action = action,
                Details = details ?? action,
                Timestamp = DateTime.UtcNow,
                IsSuccess = true
            };

            await SaveAuditLogAsync(log);
            _logger.LogInformation($"Audit action logged: {action} ({eventType}) for user {userId}");
        }
    }
}