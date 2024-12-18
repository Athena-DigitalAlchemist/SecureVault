using Microsoft.Extensions.Logging;
using Moq;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Services;
using Xunit;

namespace SecureVault.Tests.Services
{
    public class KeyManagementServiceTests
    {
        private readonly Mock<IEncryptionService> _mockEncryptionService;
        private readonly Mock<IDatabaseService> _mockDatabaseService;
        private readonly Mock<ILogger<KeyManagementService>> _mockLogger;
        private readonly KeyManagementService _keyManagementService;

        public KeyManagementServiceTests()
        {
            _mockEncryptionService = new Mock<IEncryptionService>();
            _mockDatabaseService = new Mock<IDatabaseService>();
            _mockLogger = new Mock<ILogger<KeyManagementService>>();

            _keyManagementService = new KeyManagementService(
                _mockEncryptionService.Object,
                _mockDatabaseService.Object,
                _mockLogger.Object
            );
        }

        [Fact]
        public async Task GenerateKeyAsync_ShouldReturnValidKey()
        {
            // Act
            var key = await _keyManagementService.GenerateKeyAsync();

            // Assert
            Assert.NotNull(key);
            Assert.Equal(44, key.Length); // Base64 encoded 32-byte key
        }

        [Fact]
        public async Task ValidateKeyStrengthAsync_WithValidKey_ReturnsTrue()
        {
            // Arrange
            var key = await _keyManagementService.GenerateKeyAsync();

            // Act
            var isValid = await _keyManagementService.ValidateKeyStrengthAsync(key);

            // Assert
            Assert.True(isValid);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("short")]
        [InlineData("not-base64-encoded")]
        public async Task ValidateKeyStrengthAsync_WithInvalidKey_ReturnsFalse(string invalidKey)
        {
            // Act
            var isValid = await _keyManagementService.ValidateKeyStrengthAsync(invalidKey);

            // Assert
            Assert.False(isValid);
        }
    }
}
