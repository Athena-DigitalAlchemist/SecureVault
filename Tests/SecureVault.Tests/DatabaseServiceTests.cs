using Moq;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Services;
using Xunit;

namespace SecureVault.Tests
{
    public class DatabaseServiceTests : IDisposable
    {
        private readonly string _testDbPath;
        private readonly string _testBackupPath;
        private readonly DatabaseService _databaseService;
        private readonly Mock<IEncryptionService> _mockEncryptionService;

        public DatabaseServiceTests()
        {
            var testDir = Path.Combine(Path.GetTempPath(), "SecureVaultTests", Guid.NewGuid().ToString());
            Directory.CreateDirectory(testDir);

            _testDbPath = Path.Combine(testDir, "test.db");
            _testBackupPath = Path.Combine(testDir, "backup.db");

            _mockEncryptionService = new Mock<IEncryptionService>();
            _databaseService = new DatabaseService(_testDbPath, _mockEncryptionService.Object);
        }

        [Fact]
        public async Task BackupAndRestoreDatabase_ShouldWork()
        {
            // Arrange
            await _databaseService.InitializeDatabaseAsync();

            // Create some test data
            var testNote = new SecureVault.Core.Models.SecureNote
            {
                UserId = "testUser",
                Title = "Test Note",
                EncryptedContent = "Test Content",
                Category = "Test",
                CreatedAt = DateTime.UtcNow,
                LastModified = DateTime.UtcNow
            };
            await _databaseService.SaveNoteAsync(testNote);

            // Act - Backup
            var backupResult = await _databaseService.BackupDatabaseAsync(_testBackupPath);
            Assert.True(backupResult);
            Assert.True(File.Exists(_testBackupPath));

            // Delete the original database
            File.Delete(_testDbPath);
            Assert.False(File.Exists(_testDbPath));

            // Act - Restore
            var restoreResult = await _databaseService.RestoreDatabaseAsync(_testBackupPath);
            Assert.True(restoreResult);
            Assert.True(File.Exists(_testDbPath));

            // Verify the restored data
            var notes = await _databaseService.GetNotesAsync("testUser");
            Assert.Single(notes);
            Assert.Equal("Test Note", notes[0].Title);
            Assert.Equal("Test Content", notes[0].EncryptedContent);
        }

        public void Dispose()
        {
            var testDir = Path.GetDirectoryName(_testDbPath);
            if (Directory.Exists(testDir))
            {
                Directory.Delete(testDir, true);
            }
        }
    }
}
