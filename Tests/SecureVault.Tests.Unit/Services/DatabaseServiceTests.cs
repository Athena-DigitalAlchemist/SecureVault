using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;
using SecureVault.Core.Services;
using Xunit;

namespace SecureVault.Tests.Unit.Services
{
    public class DatabaseServiceTests : IDisposable
    {
        private readonly string _testDbPath;
        private readonly string _testUserDir;
        private readonly Mock<IEncryptionService> _mockEncryptionService;
        private readonly Mock<ILogger<DatabaseService>> _mockLogger;
        private readonly DatabaseService _databaseService;

        public DatabaseServiceTests()
        {
            var testDir = Path.Combine(Path.GetTempPath(), "SecureVaultTests", Guid.NewGuid().ToString());
            _testDbPath = Path.Combine(testDir, "test.db");
            _testUserDir = Path.Combine(testDir, "users");
            
            Directory.CreateDirectory(testDir);
            
            _mockEncryptionService = new Mock<IEncryptionService>();
            _mockLogger = new Mock<ILogger<DatabaseService>>();
            
            _databaseService = new DatabaseService(
                _testDbPath,
                _testUserDir,
                _mockEncryptionService.Object,
                _mockLogger.Object
            );
        }

        public void Dispose()
        {
            var testDir = Path.GetDirectoryName(_testDbPath);
            if (Directory.Exists(testDir))
            {
                Directory.Delete(testDir, true);
            }
        }

        [Fact]
        public async Task InitializeDatabaseAsync_ShouldCreateDatabase()
        {
            // Act
            await _databaseService.InitializeDatabaseAsync();

            // Assert
            Assert.True(File.Exists(_testDbPath));
        }

        [Fact]
        public async Task CreateUser_ShouldSucceed_WithValidData()
        {
            // Arrange
            var userId = "testuser";
            var passwordHash = Convert.ToBase64String(new byte[32]);
            var salt = Convert.ToBase64String(new byte[16]);

            // Act
            await _databaseService.InitializeDatabaseAsync();
            var result = await _databaseService.CreateUserAsync(userId, passwordHash, salt);

            // Assert
            Assert.True(result);
            var userSalt = await _databaseService.GetUserSaltAsync(userId);
            Assert.Equal(salt, userSalt);
        }

        [Fact]
        public async Task ValidateUserCredentials_ShouldReturnTrue_ForValidCredentials()
        {
            // Arrange
            var userId = "testuser";
            var passwordHash = Convert.ToBase64String(new byte[32]);
            var salt = Convert.ToBase64String(new byte[16]);

            // Act
            await _databaseService.InitializeDatabaseAsync();
            await _databaseService.CreateUserAsync(userId, passwordHash, salt);
            var result = await _databaseService.ValidateUserCredentialsAsync(userId, passwordHash);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public async Task ValidateUserCredentials_ShouldReturnFalse_ForInvalidCredentials()
        {
            // Arrange
            var userId = "testuser";
            var passwordHash = Convert.ToBase64String(new byte[32]);
            var wrongHash = Convert.ToBase64String(new byte[32]);
            var salt = Convert.ToBase64String(new byte[16]);

            // Act
            await _databaseService.InitializeDatabaseAsync();
            await _databaseService.CreateUserAsync(userId, passwordHash, salt);
            var result = await _databaseService.ValidateUserCredentialsAsync(userId, wrongHash);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public async Task SavePasswordEntry_ShouldSucceed_WithValidData()
        {
            // Arrange
            await _databaseService.InitializeDatabaseAsync();
            var entry = new PasswordEntry
            {
                UserId = "testuser",
                Title = "Test Entry",
                Username = "testusername",
                EncryptedPassword = "encryptedpassword",
                Category = "Test",
                LastModified = DateTime.UtcNow
            };

            // Act
            var result = await _databaseService.SavePasswordEntryAsync(entry);
            var savedEntries = await _databaseService.GetPasswordEntriesAsync("testuser");

            // Assert
            Assert.True(result);
            Assert.Contains(savedEntries, e => e.Title == entry.Title && e.Username == entry.Username);
        }

        [Fact]
        public async Task UpdatePasswordEntry_ShouldSucceed_WithValidData()
        {
            // Arrange
            await _databaseService.InitializeDatabaseAsync();
            var entry = new PasswordEntry
            {
                Id = Guid.NewGuid().ToString(),
                UserId = "testuser",
                Title = "Test Entry",
                Username = "testusername",
                EncryptedPassword = "encryptedpassword",
                Category = "Test",
                LastModified = DateTime.UtcNow
            };
            await _databaseService.SavePasswordEntryAsync(entry);

            // Act
            entry.Title = "Updated Title";
            var result = await _databaseService.UpdatePasswordEntryAsync(entry);
            var updatedEntry = await _databaseService.GetPasswordEntryAsync(entry.Id);

            // Assert
            Assert.True(result);
            Assert.Equal("Updated Title", updatedEntry?.Title);
        }

        [Fact]
        public async Task DeletePasswordEntry_ShouldSucceed_WithValidId()
        {
            // Arrange
            await _databaseService.InitializeDatabaseAsync();
            var entry = new PasswordEntry
            {
                Id = Guid.NewGuid().ToString(),
                UserId = "testuser",
                Title = "Test Entry",
                Username = "testusername",
                EncryptedPassword = "encryptedpassword",
                Category = "Test",
                LastModified = DateTime.UtcNow
            };
            await _databaseService.SavePasswordEntryAsync(entry);

            // Act
            var result = await _databaseService.DeletePasswordEntryAsync(entry.Id);
            var deletedEntry = await _databaseService.GetPasswordEntryAsync(entry.Id);

            // Assert
            Assert.True(result);
            Assert.Null(deletedEntry);
        }

        [Fact]
        public async Task SaveAuditLog_ShouldSucceed_WithValidData()
        {
            // Arrange
            await _databaseService.InitializeDatabaseAsync();
            var log = new AuditLog
            {
                Id = Guid.NewGuid().ToString(),
                UserId = "testuser",
                Action = "Test Action",
                Details = "Test Details",
                Timestamp = DateTime.UtcNow
            };

            // Act & Assert
            await _databaseService.SaveAuditLogAsync(log);
            var logs = await _databaseService.GetAuditLogsAsync("testuser", 1);
            
            Assert.Single(logs);
            Assert.Equal(log.Action, logs[0].Action);
            Assert.Equal(log.Details, logs[0].Details);
        }

        [Fact]
        public async Task SecuritySettings_ShouldPersist()
        {
            // Arrange
            await _databaseService.InitializeDatabaseAsync();
            var key = "test_setting";
            var value = "test_value";

            // Act
            await _databaseService.UpdateSecuritySettingAsync(key, value);
            var retrievedValue = await _databaseService.RetrieveSecuritySettingAsync(key);

            // Assert
            Assert.Equal(value, retrievedValue);
        }

        [Fact]
        public async Task GetPasswordsByCategory_ShouldReturnCorrectEntries()
        {
            // Arrange
            await _databaseService.InitializeDatabaseAsync();
            var userId = "testuser";
            var entry1 = new PasswordEntry
            {
                UserId = userId,
                Title = "Test Entry 1",
                Category = "Work",
                LastModified = DateTime.UtcNow
            };
            var entry2 = new PasswordEntry
            {
                UserId = userId,
                Title = "Test Entry 2",
                Category = "Personal",
                LastModified = DateTime.UtcNow
            };

            await _databaseService.SavePasswordEntryAsync(entry1);
            await _databaseService.SavePasswordEntryAsync(entry2);

            // Act
            var workEntries = await _databaseService.GetPasswordsByCategoryAsync(userId, "Work");
            var personalEntries = await _databaseService.GetPasswordsByCategoryAsync(userId, "Personal");

            // Assert
            Assert.Single(workEntries);
            Assert.Single(personalEntries);
            Assert.Equal("Test Entry 1", workEntries[0].Title);
            Assert.Equal("Test Entry 2", personalEntries[0].Title);
        }
    }
}
