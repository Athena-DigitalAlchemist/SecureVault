using SecureVault.Core.Models;
using SecureVault.Core.Services;
using Xunit;

namespace SecureVault.Tests.Services
{
    public class DatabaseServiceTests : IDisposable
    {
        private readonly DatabaseService _databaseService;
        private readonly string _dbPath;
        private const string TestUserId = "testUser123";

        public DatabaseServiceTests()
        {
            _dbPath = Path.Combine(Path.GetTempPath(), $"securevault_test_{Guid.NewGuid()}.db");
            _databaseService = new DatabaseService(_dbPath);
            _databaseService.InitializeDatabaseAsync().Wait();
        }

        [Fact]
        public async Task SaveAndGetPassword_ShouldWorkCorrectly()
        {
            // Arrange
            var password = new PasswordEntry
            {
                UserId = TestUserId,
                Title = "Test Password",
                Username = "testuser@example.com",
                EncryptedPassword = "encryptedValue",
                Url = "https://example.com",
                Notes = "Test notes",
                LastModified = DateTime.UtcNow,
                Category = "Test Category",
                IsFavorite = true
            };

            // Act
            var id = await _databaseService.SavePasswordAsync(password);
            var retrievedPasswords = await _databaseService.GetAllPasswordsAsync(TestUserId);
            var retrievedPassword = retrievedPasswords.First();

            // Assert
            Assert.Single(retrievedPasswords);
            Assert.Equal(password.Title, retrievedPassword.Title);
            Assert.Equal(password.Username, retrievedPassword.Username);
            Assert.Equal(password.EncryptedPassword, retrievedPassword.EncryptedPassword);
            Assert.Equal(password.Url, retrievedPassword.Url);
            Assert.Equal(password.IsFavorite, retrievedPassword.IsFavorite);
            Assert.True(id > 0);
        }

        [Fact]
        public async Task SaveAndGetNote_ShouldWorkCorrectly()
        {
            // Arrange
            var note = new SecureNote
            {
                UserId = TestUserId,
                Title = "Test Note",
                EncryptedContent = "encryptedNoteContent",
                LastModified = DateTime.UtcNow,
                Category = "Personal",
                IsFavorite = true
            };

            // Act
            var id = await _databaseService.SaveNoteAsync(note);
            var retrievedNotes = await _databaseService.GetNotesAsync(TestUserId);
            var retrievedNote = retrievedNotes.First();

            // Assert
            Assert.Single(retrievedNotes);
            Assert.Equal(note.Title, retrievedNote.Title);
            Assert.Equal(note.EncryptedContent, retrievedNote.EncryptedContent);
            Assert.Equal(note.Category, retrievedNote.Category);
            Assert.Equal(note.IsFavorite, retrievedNote.IsFavorite);
            Assert.True(id > 0);
        }

        [Fact]
        public async Task SaveAndGetSecureFile_ShouldWorkCorrectly()
        {
            // Arrange
            var file = new SecureFile
            {
                UserId = TestUserId,
                FileName = "test.txt",
                EncryptedContent = new byte[] { 1, 2, 3, 4, 5 },
                FileType = "text/plain",
                LastModified = DateTime.UtcNow,
                Size = 5
            };

            // Act
            var id = await _databaseService.SaveSecureFileAsync(file, TestUserId);
            var retrievedFiles = await _databaseService.GetSecureFilesAsync(TestUserId);
            var retrievedFile = retrievedFiles.First();
            var singleFile = await _databaseService.GetSecureFileAsync(id);

            // Assert
            Assert.Single(retrievedFiles);
            Assert.Equal(file.FileName, retrievedFile.FileName);
            Assert.Equal(file.EncryptedContent, retrievedFile.EncryptedContent);
            Assert.Equal(file.FileType, retrievedFile.FileType);
            Assert.Equal(file.Size, retrievedFile.Size);
            Assert.NotNull(singleFile);
            Assert.Equal(file.FileName, singleFile.FileName);
        }

        [Fact]
        public async Task SaveAndGetBackupMetadata_ShouldWorkCorrectly()
        {
            // Arrange
            var backup = new BackupMetadata
            {
                UserId = TestUserId,
                BackupDate = DateTime.UtcNow,
                FilePath = "/path/to/backup.zip",
                Size = 1024,
                EncryptionVersion = "1.0"
            };

            // Act
            var result = await _databaseService.SaveBackupMetadataAsync(backup);
            var retrievedBackups = await _databaseService.GetBackupHistoryAsync(TestUserId);
            var retrievedBackup = retrievedBackups.First();

            // Assert
            Assert.True(result);
            Assert.Single(retrievedBackups);
            Assert.Equal(backup.FilePath, retrievedBackup.FilePath);
            Assert.Equal(backup.Size, retrievedBackup.Size);
            Assert.Equal(backup.EncryptionVersion, retrievedBackup.EncryptionVersion);
        }

        [Fact]
        public async Task SaveAndGetAuditLog_ShouldWorkCorrectly()
        {
            // Arrange
            var log = new AuditLog
            {
                UserId = TestUserId,
                Timestamp = DateTime.UtcNow,
                Action = "PasswordCreated",
                Details = "Created new password entry",
                IpAddress = "127.0.0.1"
            };

            // Act
            await _databaseService.SaveAuditLogAsync(log);
            var retrievedLogs = await _databaseService.GetAuditLogsAsync(TestUserId, 10);
            var retrievedLog = retrievedLogs.First();

            // Assert
            Assert.Single(retrievedLogs);
            Assert.Equal(log.Action, retrievedLog.Action);
            Assert.Equal(log.Details, retrievedLog.Details);
            Assert.Equal(log.IpAddress, retrievedLog.IpAddress);
        }

        [Fact]
        public async Task DeletePassword_ShouldRemovePassword()
        {
            // Arrange
            var password = new PasswordEntry
            {
                UserId = TestUserId,
                Title = "Delete Test",
                Username = "delete@test.com",
                EncryptedPassword = "toDelete",
                LastModified = DateTime.UtcNow
            };
            await _databaseService.SavePasswordAsync(password);

            // Act
            await _databaseService.DeletePasswordAsync(password.Id);
            var passwords = await _databaseService.GetAllPasswordsAsync(TestUserId);

            // Assert
            Assert.Empty(passwords);
        }

        [Fact]
        public async Task UpdatePassword_ShouldModifyExistingPassword()
        {
            // Arrange
            var password = new PasswordEntry
            {
                UserId = TestUserId,
                Title = "Original Title",
                Username = "original@test.com",
                EncryptedPassword = "original",
                LastModified = DateTime.UtcNow
            };
            var id = await _databaseService.SavePasswordAsync(password);

            // Act
            password.Id = id;
            password.Title = "Updated Title";
            password.Username = "updated@test.com";
            await _databaseService.SavePasswordAsync(password);

            var passwords = await _databaseService.GetAllPasswordsAsync(TestUserId);
            var updatedPassword = passwords.First();

            // Assert
            Assert.Single(passwords);
            Assert.Equal("Updated Title", updatedPassword.Title);
            Assert.Equal("updated@test.com", updatedPassword.Username);
        }

        [Fact]
        public async Task GetPasswordsByCategory_ShouldReturnCorrectPasswords()
        {
            // Arrange
            var passwords = new[]
            {
                new PasswordEntry
                {
                    UserId = TestUserId,
                    Title = "Work Password",
                    Category = "Work",
                    LastModified = DateTime.UtcNow,
                    EncryptedPassword = "work123"
                },
                new PasswordEntry
                {
                    UserId = TestUserId,
                    Title = "Personal Password",
                    Category = "Personal",
                    LastModified = DateTime.UtcNow,
                    EncryptedPassword = "personal123"
                }
            };

            foreach (var pwd in passwords)
            {
                await _databaseService.SavePasswordAsync(pwd);
            }

            // Act
            var workPasswords = await _databaseService.GetPasswordsByCategoryAsync(TestUserId, "Work");
            var personalPasswords = await _databaseService.GetPasswordsByCategoryAsync(TestUserId, "Personal");

            // Assert
            Assert.Single(workPasswords);
            Assert.Single(personalPasswords);
            Assert.Equal("Work Password", workPasswords.First().Title);
            Assert.Equal("Personal Password", personalPasswords.First().Title);
        }

        [Fact]
        public async Task DeleteSecureFile_ShouldRemoveFile()
        {
            // Arrange
            var file = new SecureFile
            {
                UserId = TestUserId,
                FileName = "delete_test.txt",
                EncryptedContent = new byte[] { 1, 2, 3 },
                FileType = "text/plain",
                LastModified = DateTime.UtcNow,
                Size = 3
            };
            var id = await _databaseService.SaveSecureFileAsync(file, TestUserId);

            // Act
            await _databaseService.DeleteSecureFileAsync(id);
            var files = await _databaseService.GetSecureFilesAsync(TestUserId);

            // Assert
            Assert.Empty(files);
        }

        [Fact]
        public async Task DeleteBackupMetadata_ShouldRemoveBackup()
        {
            // Arrange
            var backup = new BackupMetadata
            {
                UserId = TestUserId,
                BackupDate = DateTime.UtcNow,
                FilePath = "/path/to/delete.zip",
                Size = 1024,
                EncryptionVersion = "1.0"
            };
            await _databaseService.SaveBackupMetadataAsync(backup);
            var backups = await _databaseService.GetBackupHistoryAsync(TestUserId);
            var id = backups.First().Id;

            // Act
            var result = await _databaseService.DeleteBackupMetadataAsync(id);
            backups = await _databaseService.GetBackupHistoryAsync(TestUserId);

            // Assert
            Assert.True(result);
            Assert.Empty(backups);
        }

        public void Dispose()
        {
            if (File.Exists(_dbPath))
            {
                File.Delete(_dbPath);
            }
        }
    }
}
