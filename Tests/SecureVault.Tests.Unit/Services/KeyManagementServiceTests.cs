using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Services;
using Xunit;

namespace SecureVault.Tests.Unit.Services
{
    public class KeyManagementServiceTests
    {
        private readonly Mock<IEncryptionService> _mockEncryptionService;
        private readonly Mock<ILogger<KeyManagementService>> _mockLogger;
        private readonly KeyManagementService _keyManagementService;

        public KeyManagementServiceTests()
        {
            _mockEncryptionService = new Mock<IEncryptionService>();
            _mockLogger = new Mock<ILogger<KeyManagementService>>();
            _keyManagementService = new KeyManagementService(_mockEncryptionService.Object, _mockLogger.Object);
        }

        [Fact]
        public async Task GenerateMasterKeyAsync_ShouldGenerateValidKey()
        {
            // Arrange
            var password = "TestPassword123!";
            var salt = Convert.ToBase64String(new byte[32]); // 256-bit salt
            _mockEncryptionService.Setup(x => x.GenerateSaltAsync())
                .ReturnsAsync(Convert.FromBase64String(salt));

            // Act
            var key = await _keyManagementService.GenerateMasterKeyAsync(password);

            // Assert
            Assert.NotNull(key);
            Assert.True(await _keyManagementService.ValidateKeyStrengthAsync(key));
            _mockEncryptionService.Verify(x => x.GenerateSaltAsync(), Times.Once);
        }

        [Fact]
        public async Task ValidateKeyStrength_ShouldReturnTrue_ForValidKey()
        {
            // Arrange
            var validKey = Convert.ToBase64String(new byte[32]); // 256-bit key

            // Act
            var result = await _keyManagementService.ValidateKeyStrengthAsync(validKey);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public async Task ValidateKeyStrength_ShouldReturnFalse_ForInvalidKey()
        {
            // Arrange
            var invalidKey = Convert.ToBase64String(new byte[16]); // 128-bit key (too short)

            // Act
            var result = await _keyManagementService.ValidateKeyStrengthAsync(invalidKey);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public async Task BackupAndRestoreKey_ShouldWorkCorrectly()
        {
            // Arrange
            var originalKey = Convert.ToBase64String(new byte[32]);
            var encryptedBackup = "encrypted_backup_data";
            var decryptedBackup = $"{DateTime.UtcNow:o}|1.0|{originalKey}";

            _mockEncryptionService.Setup(x => x.EncryptAsync(It.IsAny<string>(), originalKey))
                .ReturnsAsync(encryptedBackup);
            _mockEncryptionService.Setup(x => x.DecryptAsync(encryptedBackup, "1.0"))
                .ReturnsAsync(decryptedBackup);

            // Act
            var backup = await _keyManagementService.BackupKeyAsync(originalKey);
            var restoredKey = await _keyManagementService.RestoreKeyAsync(backup);

            // Assert
            Assert.Equal(originalKey, restoredKey);
            _mockEncryptionService.Verify(x => x.EncryptAsync(It.IsAny<string>(), originalKey), Times.Once);
            _mockEncryptionService.Verify(x => x.DecryptAsync(encryptedBackup, "1.0"), Times.Once);
        }

        [Fact]
        public async Task RotateKey_ShouldSucceed_WithValidKeys()
        {
            // Arrange
            var currentKey = Convert.ToBase64String(new byte[32]);
            var newKey = Convert.ToBase64String(new byte[32]);

            // Act
            var result = await _keyManagementService.RotateKeyAsync(currentKey, newKey);

            // Assert
            Assert.True(result);
            var version = await _keyManagementService.GetCurrentKeyVersionAsync();
            Assert.NotEqual("1.0", version); // Version should be updated
        }

        [Fact]
        public async Task RotateKey_ShouldFail_WithInvalidKeys()
        {
            // Arrange
            var currentKey = Convert.ToBase64String(new byte[16]); // Invalid key size
            var newKey = Convert.ToBase64String(new byte[32]);

            // Act
            var result = await _keyManagementService.RotateKeyAsync(currentKey, newKey);

            // Assert
            Assert.False(result);
            var version = await _keyManagementService.GetCurrentKeyVersionAsync();
            Assert.Equal("1.0", version); // Version should not change
        }

        [Fact]
        public async Task DeriveKeyFromPassword_ShouldGenerateConsistentKeys()
        {
            // Arrange
            var password = "TestPassword123!";
            var salt = Convert.ToBase64String(new byte[32]);

            // Act
            var key1 = await _keyManagementService.DeriveKeyFromPasswordAsync(password, salt);
            var key2 = await _keyManagementService.DeriveKeyFromPasswordAsync(password, salt);

            // Assert
            Assert.Equal(key1, key2);
            Assert.True(await _keyManagementService.ValidateKeyStrengthAsync(key1));
            Assert.True(await _keyManagementService.ValidateKeyStrengthAsync(key2));
        }
    }
}
