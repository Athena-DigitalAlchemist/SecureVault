using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Generic;
using Moq;
using Xunit;
using SecureVault.Core.Services;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;

namespace SecureVault.Tests.Unit.Services
{
    public class SecureFileStorageServiceTests : IDisposable
    {
        private readonly Mock<IEncryptionService> _mockEncryptionService;
        private readonly Mock<IDatabaseService> _mockDatabaseService;
        private readonly Mock<IAuditLogService> _mockAuditLogService;
        private readonly string _testStoragePath;
        private readonly SecureFileStorageService _service;
        private readonly string _testUserId;

        public SecureFileStorageServiceTests()
        {
            _mockEncryptionService = new Mock<IEncryptionService>();
            _mockDatabaseService = new Mock<IDatabaseService>();
            _mockAuditLogService = new Mock<IAuditLogService>();
            _testStoragePath = Path.Combine(Path.GetTempPath(), "SecureVaultTests", Guid.NewGuid().ToString());
            _testUserId = "test-user-id";
            
            Directory.CreateDirectory(_testStoragePath);
            _service = new SecureFileStorageService(
                _mockEncryptionService.Object,
                _mockDatabaseService.Object,
                _mockAuditLogService.Object,
                _testStoragePath);
        }

        public void Dispose()
        {
            if (Directory.Exists(_testStoragePath))
            {
                Directory.Delete(_testStoragePath, true);
            }
        }

        [Fact]
        public async Task StoreFileAsync_ValidFile_StoresAndEncryptsFile()
        {
            // Arrange
            var sourceFilePath = Path.Combine(_testStoragePath, "test.txt");
            File.WriteAllText(sourceFilePath, "Test content");
            var testFile = new SecureFile
            {
                Id = "1",
                UserId = _testUserId,
                FileName = "test.txt",
                FileType = "txt",
                FileSize = new FileInfo(sourceFilePath).Length
            };

            _mockDatabaseService
                .Setup(x => x.SaveSecureFileAsync(It.IsAny<SecureFile>(), It.IsAny<string>()))
                .ReturnsAsync(testFile);

            // Act
            var result = await _service.StoreFileAsync(sourceFilePath, _testUserId);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(testFile.Id, result.Id);
            Assert.Equal(testFile.FileName, result.FileName);
            _mockEncryptionService.Verify(
                x => x.EncryptStreamAsync(
                    It.IsAny<Stream>(),
                    It.IsAny<Stream>(),
                    It.IsAny<byte[]>()),
                Times.Once);
            _mockAuditLogService.Verify(
                x => x.LogEventAsync(
                    _testUserId,
                    AuditEventType.FileUploaded,
                    It.IsAny<string>()),
                Times.Once);
        }

        [Fact]
        public async Task StoreFileAsync_NonExistentFile_ThrowsFileNotFoundException()
        {
            // Arrange
            var nonExistentPath = Path.Combine(_testStoragePath, "nonexistent.txt");

            // Act & Assert
            await Assert.ThrowsAsync<FileNotFoundException>(
                () => _service.StoreFileAsync(nonExistentPath, _testUserId));
        }

        [Fact]
        public async Task RetrieveFileAsync_ValidFile_DecryptsAndReturnsFile()
        {
            // Arrange
            var encryptedPath = Path.Combine(_testStoragePath, "encrypted.bin");
            File.WriteAllText(encryptedPath, "Encrypted content");
            var destinationPath = Path.Combine(_testStoragePath, "decrypted.txt");
            
            var secureFile = new SecureFile
            {
                Id = "1",
                UserId = _testUserId,
                FileName = "test.txt",
                EncryptedPath = encryptedPath,
                Hash = "test-hash"
            };

            _mockDatabaseService
                .Setup(x => x.GetSecureFileAsync(It.IsAny<int>()))
                .ReturnsAsync(secureFile);

            // Act
            var result = await _service.RetrieveFileAsync(secureFile, destinationPath);

            // Assert
            Assert.Equal(destinationPath, result);
            _mockEncryptionService.Verify(
                x => x.DecryptStreamAsync(
                    It.IsAny<Stream>(),
                    It.IsAny<Stream>(),
                    It.IsAny<byte[]>()),
                Times.Once);
            _mockAuditLogService.Verify(
                x => x.LogEventAsync(
                    _testUserId,
                    AuditEventType.FileDownloaded,
                    It.IsAny<string>()),
                Times.Once);
        }

        [Fact]
        public async Task DeleteFileAsync_ExistingFile_DeletesFileAndMetadata()
        {
            // Arrange
            var encryptedPath = Path.Combine(_testStoragePath, "to-delete.bin");
            File.WriteAllText(encryptedPath, "Content to delete");
            
            var secureFile = new SecureFile
            {
                Id = "1",
                UserId = _testUserId,
                FileName = "test.txt",
                EncryptedPath = encryptedPath
            };

            _mockDatabaseService
                .Setup(x => x.GetSecureFileAsync(It.IsAny<int>()))
                .ReturnsAsync(secureFile);

            // Act
            var result = await _service.DeleteFileAsync(secureFile);

            // Assert
            Assert.True(result);
            Assert.False(File.Exists(encryptedPath));
            _mockAuditLogService.Verify(
                x => x.LogEventAsync(
                    _testUserId,
                    AuditEventType.FileDeleted,
                    It.IsAny<string>()),
                Times.Once);
        }

        [Fact]
        public async Task ListFilesAsync_ReturnsUserFiles()
        {
            // Arrange
            var expectedFiles = new List<SecureFile>
            {
                new SecureFile { Id = "1", UserId = _testUserId, FileName = "file1.txt" },
                new SecureFile { Id = "2", UserId = _testUserId, FileName = "file2.txt" }
            };

            _mockDatabaseService
                .Setup(x => x.GetSecureFilesAsync(_testUserId))
                .ReturnsAsync(expectedFiles);

            // Act
            var result = await _service.ListFilesAsync(_testUserId);

            // Assert
            Assert.Equal(expectedFiles.Count, result.Count);
            Assert.Equal(expectedFiles[0].FileName, result[0].FileName);
            Assert.Equal(expectedFiles[1].FileName, result[1].FileName);
        }

        [Fact]
        public async Task ValidateFileIntegrityAsync_ValidFile_ReturnsTrue()
        {
            // Arrange
            var encryptedPath = Path.Combine(_testStoragePath, "valid.bin");
            File.WriteAllText(encryptedPath, "Valid content");
            
            var secureFile = new SecureFile
            {
                Id = "1",
                UserId = _testUserId,
                FileName = "test.txt",
                EncryptedPath = encryptedPath,
                Hash = "test-hash"
            };

            // Act
            var result = await _service.ValidateFileIntegrityAsync(secureFile);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public async Task ValidateFileIntegrityAsync_NonExistentFile_ReturnsFalse()
        {
            // Arrange
            var secureFile = new SecureFile
            {
                Id = "1",
                UserId = _testUserId,
                FileName = "test.txt",
                EncryptedPath = Path.Combine(_testStoragePath, "nonexistent.bin"),
                Hash = "test-hash"
            };

            // Act
            var result = await _service.ValidateFileIntegrityAsync(secureFile);

            // Assert
            Assert.False(result);
        }
    }
}
