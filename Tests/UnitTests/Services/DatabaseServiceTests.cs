using System;
using System.IO;
using System.Threading.Tasks;
using Dapper;
using Microsoft.Data.Sqlite;
using SecureVault.Core.Exceptions;
using SecureVault.Core.Models;
using SecureVault.Core.Services;
using Xunit;

namespace SecureVault.Tests.Services
{
    public class DatabaseServiceTests : IDisposable
    {
        private readonly string _testDbPath;
        private readonly string _testUserDir;
        private readonly DatabaseService _service;

        public DatabaseServiceTests()
        {
            // Setup test database in memory
            _testDbPath = Path.Combine(Path.GetTempPath(), $"test_db_{Guid.NewGuid()}.db");
            _testUserDir = Path.Combine(Path.GetTempPath(), $"test_user_{Guid.NewGuid()}");
            _service = new DatabaseService(_testDbPath, _testUserDir);
        }

        public void Dispose()
        {
            // Cleanup test files
            if (File.Exists(_testDbPath))
                File.Delete(_testDbPath);
            if (Directory.Exists(_testUserDir))
                Directory.Delete(_testUserDir, true);
        }

        [Fact]
        public async Task InitializeDatabaseAsync_ShouldCreateTables()
        {
            // Arrange & Act
            await _service.InitializeDatabaseAsync();

            // Assert
            using var connection = new SqliteConnection($"Data Source={_testDbPath}");
            await connection.OpenAsync();
            
            var tableCount = await connection.QueryFirstAsync<int>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'");
            Assert.Equal(7, tableCount); // We expect 7 tables: Users, SecureFiles, SecuritySettings, AuditLogs, PasswordEntries, Notes, BackupMetadata
        }

        [Fact]
        public async Task CreateUserAsync_WithValidData_ShouldSucceed()
        {
            // Arrange
            await _service.InitializeDatabaseAsync();
            var userId = Guid.NewGuid().ToString();
            var passwordHash = "hashedPassword";
            var salt = "salt";

            // Act
            var result = await _service.CreateUserAsync(userId, passwordHash, salt);

            // Assert
            Assert.True(result);
            var storedSalt = await _service.GetUserSaltAsync(userId);
            Assert.Equal(salt, storedSalt);
        }

        [Fact]
        public async Task CreateUserAsync_WithNullUserId_ShouldThrowArgumentException()
        {
            // Arrange
            await _service.InitializeDatabaseAsync();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() => 
                _service.CreateUserAsync(null!, "hash", "salt"));
        }

        [Fact]
        public async Task StorePasswordEntryAsync_WithValidData_ShouldSucceed()
        {
            // Arrange
            await _service.InitializeDatabaseAsync();
            var entry = new PasswordEntry
            {
                UserId = Guid.NewGuid().ToString(),
                Title = "Test Password",
                Username = "testuser",
                EncryptedPassword = "encryptedPassword",
                Website = "https://example.com"
            };

            // Act
            var result = await _service.StorePasswordEntryAsync(entry);

            // Assert
            Assert.True(result);
            var storedEntry = await _service.GetPasswordEntryAsync(entry.Id);
            Assert.NotNull(storedEntry);
            Assert.Equal(entry.Title, storedEntry.Title);
            Assert.Equal(entry.Username, storedEntry.Username);
        }

        [Fact]
        public async Task SaveAuditLogAsync_WithValidData_ShouldSucceed()
        {
            // Arrange
            await _service.InitializeDatabaseAsync();
            var log = new AuditLog
            {
                UserId = Guid.NewGuid().ToString(),
                Action = "Test Action",
                Details = "Test Details"
            };

            // Act
            var result = await _service.SaveAuditLogAsync(log);

            // Assert
            Assert.True(result);
            var logs = await _service.GetAuditLogsAsync(log.UserId, 1);
            Assert.Single(logs);
            Assert.Equal(log.Action, logs[0].Action);
        }

        [Fact]
        public async Task BackupAndRestoreDatabase_ShouldMaintainData()
        {
            // Arrange
            await _service.InitializeDatabaseAsync();
            var userId = Guid.NewGuid().ToString();
            await _service.CreateUserAsync(userId, "hash", "salt");
            var backupPath = Path.Combine(Path.GetTempPath(), $"backup_{Guid.NewGuid()}.db");

            try
            {
                // Act
                var backupResult = await _service.BackupDatabaseAsync(backupPath);
                Assert.True(backupResult);

                // Delete the original user
                using (var conn = new SqliteConnection($"Data Source={_testDbPath}"))
                {
                    await conn.OpenAsync();
                    await conn.ExecuteAsync("DELETE FROM Users WHERE Id = @Id", new { Id = userId });
                }

                var restoreResult = await _service.RestoreDatabaseAsync(backupPath);
                Assert.True(restoreResult);

                // Assert
                var salt = await _service.GetUserSaltAsync(userId);
                Assert.Equal("salt", salt);
            }
            finally
            {
                if (File.Exists(backupPath))
                    File.Delete(backupPath);
            }
        }

        [Fact]
        public async Task ValidatePasswordAsync_WithMatchingHash_ShouldReturnTrue()
        {
            // Arrange
            var password = "testPassword";
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            var hash = Convert.ToBase64String(hashBytes);

            // Act
            var result = await _service.ValidatePasswordAsync(password, hash);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public async Task UpdateSecuritySettingAsync_WithValidData_ShouldSucceed()
        {
            // Arrange
            await _service.InitializeDatabaseAsync();
            var key = "TestSetting";
            var value = "TestValue";

            // Act
            var saveResult = await _service.UpdateSecuritySettingAsync(key, value);
            var retrievedValue = await _service.GetSecuritySettingAsync(key);

            // Assert
            Assert.True(saveResult);
            Assert.Equal(value, retrievedValue);
        }
    }
}
