using Microsoft.Extensions.Logging;
using Moq;
using SecureVault.Core.Models;
using SecureVault.Core.Services;

namespace SecureVault.Tests.Services
{
    [TestClass]
    public class BackupServiceTests
    {
        private Mock<ILogger<BackupService>> _loggerMock;
        private Mock<IDatabaseService> _databaseServiceMock;
        private Mock<IEncryptionService> _encryptionServiceMock;
        private BackupService _backupService;
        private string _testBackupDir;

        [TestInitialize]
        public void Setup()
        {
            _loggerMock = new Mock<ILogger<BackupService>>();
            _databaseServiceMock = new Mock<IDatabaseService>();
            _encryptionServiceMock = new Mock<IEncryptionService>();

            _testBackupDir = Path.Combine(Path.GetTempPath(), "securevault_test_backups");
            Directory.CreateDirectory(_testBackupDir);

            _backupService = new BackupService(
                _loggerMock.Object,
                _databaseServiceMock.Object,
                _encryptionServiceMock.Object,
                _testBackupDir);
        }

        [TestMethod]
        public async Task CreateBackup_ShouldCreateBackupFile()
        {
            // Arrange
            var userId = "testUser";
            var testData = "Test backup data";
            var encryptedData = "Encrypted test data";

            _encryptionServiceMock.Setup(e => e.EncryptAsync(It.IsAny<string>()))
                .ReturnsAsync(encryptedData);

            _databaseServiceMock.Setup(d => d.SaveBackupMetadataAsync(It.IsAny<BackupMetadata>()))
                .ReturnsAsync(true);

            // Act
            var result = await _backupService.CreateBackupAsync(userId, testData);

            // Assert
            Assert.IsTrue(result.Success);
            Assert.IsNotNull(result.BackupPath);
            Assert.IsTrue(File.Exists(result.BackupPath));

            _databaseServiceMock.Verify(
                d => d.SaveBackupMetadataAsync(It.Is<BackupMetadata>(
                    m => m.UserId == userId &&
                         m.Status == "Completed")),
                Times.Once);
        }

        [TestMethod]
        public async Task RestoreBackup_ShouldRestoreFromBackupFile()
        {
            // Arrange
            var userId = "testUser";
            var backupContent = "Encrypted backup content";
            var decryptedContent = "Decrypted backup content";
            var backupPath = Path.Combine(_testBackupDir, "test_backup.bak");

            await File.WriteAllTextAsync(backupPath, backupContent);

            _encryptionServiceMock.Setup(e => e.DecryptAsync(backupContent))
                .ReturnsAsync(decryptedContent);

            var metadata = new BackupMetadata
            {
                UserId = userId,
                BackupPath = backupPath,
                CreatedAt = DateTime.UtcNow,
                Version = "1.0",
                Size = backupContent.Length,
                Status = "Completed"
            };

            // Act
            var result = await _backupService.RestoreBackupAsync(metadata);

            // Assert
            Assert.IsTrue(result.Success);
            Assert.AreEqual(decryptedContent, result.RestoredData);
        }

        [TestMethod]
        public async Task GetBackupHistory_ShouldReturnUserBackups()
        {
            // Arrange
            var userId = "testUser";
            var backups = new[]
            {
                new BackupMetadata
                {
                    UserId = userId,
                    BackupPath = "backup1.bak",
                    CreatedAt = DateTime.UtcNow.AddDays(-1),
                    Version = "1.0",
                    Status = "Completed"
                },
                new BackupMetadata
                {
                    UserId = userId,
                    BackupPath = "backup2.bak",
                    CreatedAt = DateTime.UtcNow,
                    Version = "1.0",
                    Status = "Completed"
                }
            };

            _databaseServiceMock.Setup(d => d.GetBackupHistoryAsync(userId))
                .ReturnsAsync(backups);

            // Act
            var history = await _backupService.GetBackupHistoryAsync(userId);

            // Assert
            Assert.AreEqual(2, history.Count);
            Assert.AreEqual("backup2.bak", history[0].BackupPath);
            Assert.AreEqual("backup1.bak", history[1].BackupPath);
        }

        [TestMethod]
        public async Task DeleteBackup_ShouldRemoveBackupFile()
        {
            // Arrange
            var backupPath = Path.Combine(_testBackupDir, "delete_test.bak");
            await File.WriteAllTextAsync(backupPath, "Test content");

            var metadata = new BackupMetadata
            {
                UserId = "testUser",
                BackupPath = backupPath,
                CreatedAt = DateTime.UtcNow,
                Version = "1.0",
                Status = "Completed"
            };

            _databaseServiceMock.Setup(d => d.DeleteBackupMetadataAsync(It.IsAny<int>()))
                .ReturnsAsync(true);

            // Act
            var result = await _backupService.DeleteBackupAsync(metadata);

            // Assert
            Assert.IsTrue(result);
            Assert.IsFalse(File.Exists(backupPath));
            _databaseServiceMock.Verify(
                d => d.DeleteBackupMetadataAsync(It.IsAny<int>()),
                Times.Once);
        }

        [TestCleanup]
        public void Cleanup()
        {
            try
            {
                if (Directory.Exists(_testBackupDir))
                {
                    Directory.Delete(_testBackupDir, true);
                }
            }
            catch (IOException)
            {
                // Ignore cleanup errors
            }
        }
    }
}
