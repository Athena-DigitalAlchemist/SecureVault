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
    public class BackupServiceTests : IDisposable
    {
        private readonly Mock<IDatabaseService> _mockDatabaseService;
        private readonly Mock<IEncryptionService> _mockEncryptionService;
        private readonly Mock<ISecureFileStorageService> _mockFileStorageService;
        private readonly Mock<IAuditLogService> _mockAuditLogService;
        private readonly Mock<IKeyManagementService> _mockKeyManagementService;
        private readonly Mock<IBackupCredentialService> _mockBackupCredentialService;
        private readonly Mock<ILogger<BackupService>> _mockLogger;
        private readonly string _testBackupDir;
        private readonly string _testFileStorageDir;
        private readonly BackupService _backupService;

        public BackupServiceTests()
        {
            _testBackupDir = Path.Combine(Path.GetTempPath(), "SecureVaultTests", "Backups", Guid.NewGuid().ToString());
            _testFileStorageDir = Path.Combine(Path.GetTempPath(), "SecureVaultTests", "Files", Guid.NewGuid().ToString());

            Directory.CreateDirectory(_testBackupDir);
            Directory.CreateDirectory(_testFileStorageDir);

            _mockDatabaseService = new Mock<IDatabaseService>();
            _mockEncryptionService = new Mock<IEncryptionService>();
            _mockFileStorageService = new Mock<ISecureFileStorageService>();
            _mockAuditLogService = new Mock<IAuditLogService>();
            _mockKeyManagementService = new Mock<IKeyManagementService>();
            _mockBackupCredentialService = new Mock<IBackupCredentialService>();
            _mockLogger = new Mock<ILogger<BackupService>>();

            _backupService = new BackupService(
                _mockDatabaseService.Object,
                _mockEncryptionService.Object,
                _mockFileStorageService.Object,
                _mockAuditLogService.Object,
                _mockKeyManagementService.Object,
                _mockBackupCredentialService.Object,
                _testBackupDir,
                _testFileStorageDir,
                _mockLogger.Object
            );

            // Setup common mocks
            _mockEncryptionService.Setup(x => x.GenerateSalt()).Returns(new byte[16]);
            _mockEncryptionService.Setup(x => x.HashPassword(It.IsAny<string>(), It.IsAny<byte[]>()))
                .Returns<string, byte[]>((pwd, _) => Convert.ToBase64String(new byte[32]));
            _mockKeyManagementService.Setup(x => x.GetCurrentKeyAsync())
                .ReturnsAsync(Convert.ToBase64String(new byte[32]));
        }

        public void Dispose()
        {
            if (Directory.Exists(_testBackupDir))
            {
                Directory.Delete(_testBackupDir, true);
            }
            if (Directory.Exists(_testFileStorageDir))
            {
                Directory.Delete(_testFileStorageDir, true);
            }
        }

        [Fact]
        public async Task CreateBackup_ShouldCreateValidBackupFile()
        {
            // Arrange
            var userId = "testuser";
            var password = "testpassword";
            var dbBackupPath = Path.Combine(_testBackupDir, "database.bak");
            var filesBackupPath = Path.Combine(_testBackupDir, "files.bak");

            _mockDatabaseService.Setup(x => x.BackupDatabaseAsync(It.IsAny<string>()))
                .Callback<string>(path => File.WriteAllText(path, "test database backup"));

            _mockFileStorageService.Setup(x => x.BackupFilesAsync(userId, It.IsAny<string>(), It.IsAny<string>()))
                .Callback<string, string, string>((_, path, __) => File.WriteAllText(path, "test files backup"));

            // Act
            var backupPath = await _backupService.CreateBackupAsync(userId, password);

            // Assert
            Assert.True(File.Exists(backupPath));
            Assert.EndsWith(".svbak", backupPath);

            _mockDatabaseService.Verify(x => x.BackupDatabaseAsync(It.IsAny<string>()), Times.Once);
            _mockFileStorageService.Verify(x => x.BackupFilesAsync(userId, It.IsAny<string>(), It.IsAny<string>()), Times.Once);
            _mockAuditLogService.Verify(x => x.LogEventAsync(userId, AuditEventType.SecuritySettingUpdated, It.IsAny<string>()), Times.Once);
        }

        [Fact]
        public async Task RestoreBackup_ShouldRestoreValidBackup()
        {
            // Arrange
            var userId = "testuser";
            var password = "testpassword";
            var backupPath = await _backupService.CreateBackupAsync(userId, password);

            // Setup restore validation
            _mockBackupCredentialService.Setup(x => x.GetBackupPasswordAsync(backupPath))
                .ReturnsAsync(password);

            // Act
            var result = await _backupService.RestoreBackupAsync(backupPath, password);

            // Assert
            Assert.True(result);
            _mockDatabaseService.Verify(x => x.RestoreDatabaseAsync(It.IsAny<string>()), Times.Once);
            _mockFileStorageService.Verify(x => x.RestoreFilesAsync(It.IsAny<string>(), userId, It.IsAny<string>()), Times.Once);
            _mockAuditLogService.Verify(x => x.LogEventAsync(userId, AuditEventType.SecuritySettingUpdated, It.IsAny<string>()), Times.AtLeastOnce);
        }

        [Fact]
        public async Task ValidateBackup_ShouldReturnTrue_ForValidBackup()
        {
            // Arrange
            var userId = "testuser";
            var password = "testpassword";
            var backupPath = await _backupService.CreateBackupAsync(userId, password);

            // Act
            var isValid = await _backupService.ValidateBackupAsync(backupPath, password);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public async Task ValidateBackup_ShouldReturnFalse_ForInvalidPassword()
        {
            // Arrange
            var userId = "testuser";
            var password = "testpassword";
            var wrongPassword = "wrongpassword";
            var backupPath = await _backupService.CreateBackupAsync(userId, password);

            // Act
            var isValid = await _backupService.ValidateBackupAsync(backupPath, wrongPassword);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public async Task ListBackups_ShouldReturnAllValidBackups()
        {
            // Arrange
            var userId = "testuser";
            var password = "testpassword";
            var backup1 = await _backupService.CreateBackupAsync(userId, password);
            var backup2 = await _backupService.CreateBackupAsync(userId, password);

            // Create an invalid backup file
            var invalidBackup = Path.Combine(_testBackupDir, "invalid.svbak");
            File.WriteAllText(invalidBackup, "invalid backup content");

            // Act
            var backups = await _backupService.ListBackupsAsync();

            // Assert
            Assert.Equal(2, backups.Count);
            Assert.Contains(backup1, backups);
            Assert.Contains(backup2, backups);
            Assert.DoesNotContain(invalidBackup, backups);
        }

        [Fact]
        public async Task ConfigureAutomaticBackup_ShouldSaveValidConfiguration()
        {
            // Arrange
            var interval = TimeSpan.FromHours(24);
            var location = Path.Combine(_testBackupDir, "auto");

            // Act
            await _backupService.ConfigureAutomaticBackupAsync(interval, location);

            // Assert
            Assert.True(Directory.Exists(location));
            _mockDatabaseService.Verify(x => x.SaveBackupConfigurationAsync(It.Is<BackupConfiguration>(
                config => config.Interval == interval && 
                         config.Location == location && 
                         config.IsEnabled
            )), Times.Once);
            _mockAuditLogService.Verify(x => x.LogEventAsync(
                "system",
                AuditEventType.SecuritySettingUpdated,
                It.IsAny<string>()
            ), Times.Once);
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(0)]
        public async Task ConfigureAutomaticBackup_ShouldThrowException_ForInvalidInterval(int hours)
        {
            // Arrange
            var interval = TimeSpan.FromHours(hours);
            var location = Path.Combine(_testBackupDir, "auto");

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() =>
                _backupService.ConfigureAutomaticBackupAsync(interval, location));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public async Task ConfigureAutomaticBackup_ShouldThrowException_ForInvalidLocation(string location)
        {
            // Arrange
            var interval = TimeSpan.FromHours(24);

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() =>
                _backupService.ConfigureAutomaticBackupAsync(interval, location));
        }

        [Fact]
        public async Task VerifyBackup_ShouldReturnTrue_ForValidBackup()
        {
            // Arrange
            var userId = "testuser";
            var password = "testpassword";
            var backupPath = await _backupService.CreateBackupAsync(userId, password);

            _mockBackupCredentialService.Setup(x => x.GetBackupPasswordAsync(backupPath))
                .ReturnsAsync(password);

            // Act
            var isValid = await _backupService.VerifyBackupAsync(backupPath);

            // Assert
            Assert.True(isValid);
            _mockLogger.Verify(x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString().Contains("Backup verification successful")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()
            ), Times.Once);
        }

        [Fact]
        public async Task VerifyBackup_ShouldReturnFalse_WhenBackupPasswordNotFound()
        {
            // Arrange
            var userId = "testuser";
            var password = "testpassword";
            var backupPath = await _backupService.CreateBackupAsync(userId, password);

            _mockBackupCredentialService.Setup(x => x.GetBackupPasswordAsync(backupPath))
                .ReturnsAsync((string)null);

            // Act
            var isValid = await _backupService.VerifyBackupAsync(backupPath);

            // Assert
            Assert.False(isValid);
            _mockLogger.Verify(x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((o, t) => o.ToString().Contains("Backup password not found")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()
            ), Times.Once);
        }
    }
}
