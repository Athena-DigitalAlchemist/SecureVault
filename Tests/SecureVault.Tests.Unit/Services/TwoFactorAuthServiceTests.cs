using System;
using System.Linq;
using System.Threading.Tasks;
using Moq;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;
using SecureVault.Core.Services;
using Xunit;

namespace SecureVault.Tests.Unit.Services
{
    public class TwoFactorAuthServiceTests
    {
        private readonly Mock<IDatabaseService> _mockDatabaseService;
        private readonly Mock<IEncryptionService> _mockEncryptionService;
        private readonly Mock<IAuditLogService> _mockAuditLogService;
        private readonly TwoFactorAuthService _twoFactorAuthService;

        public TwoFactorAuthServiceTests()
        {
            _mockDatabaseService = new Mock<IDatabaseService>();
            _mockEncryptionService = new Mock<IEncryptionService>();
            _mockAuditLogService = new Mock<IAuditLogService>();

            _twoFactorAuthService = new TwoFactorAuthService(
                _mockDatabaseService.Object,
                _mockEncryptionService.Object,
                _mockAuditLogService.Object
            );
        }

        [Fact]
        public async Task GenerateSecretKey_ShouldReturnValidBase32String()
        {
            // Act
            var secretKey = await _twoFactorAuthService.GenerateSecretKeyAsync();

            // Assert
            Assert.NotNull(secretKey);
            Assert.Matches("^[A-Z2-7]+$", secretKey); // Base32 alphabet
            Assert.True(secretKey.Length >= 16); // Minimum length for security
        }

        [Fact]
        public async Task GenerateQrCodeUri_ShouldReturnValidUri()
        {
            // Arrange
            var secretKey = "ABCDEFGHIJKLMNOP";
            var username = "test@example.com";

            // Act
            var uri = await _twoFactorAuthService.GenerateQrCodeUriAsync(secretKey, username);

            // Assert
            Assert.NotNull(uri);
            Assert.StartsWith("otpauth://totp/", uri);
            Assert.Contains(secretKey, uri);
            Assert.Contains(Uri.EscapeDataString(username), uri);
        }

        [Fact]
        public async Task EnableTwoFactor_ShouldStoreSecretKey()
        {
            // Arrange
            var userId = "testuser";
            string storedKey = null;
            _mockDatabaseService
                .Setup(x => x.UpdateSecuritySettingAsync($"2FA_SECRET_{userId}", It.IsAny<string>()))
                .Callback<string, string>((_, key) => storedKey = key);

            // Act
            var result = await _twoFactorAuthService.EnableTwoFactorAsync(userId);

            // Assert
            Assert.True(result);
            Assert.NotNull(storedKey);
            _mockDatabaseService.Verify(
                x => x.UpdateSecuritySettingAsync($"2FA_SECRET_{userId}", It.IsAny<string>()),
                Times.Once);
        }

        [Fact]
        public async Task DisableTwoFactor_ShouldRemoveSecretKey()
        {
            // Arrange
            var userId = "testuser";

            // Act
            var result = await _twoFactorAuthService.DisableTwoFactorAsync(userId);

            // Assert
            Assert.True(result);
            _mockDatabaseService.Verify(
                x => x.UpdateSecuritySettingAsync($"2FA_SECRET_{userId}", null),
                Times.Once);
        }

        [Fact]
        public async Task IsTwoFactorEnabled_ShouldReturnTrue_WhenKeyExists()
        {
            // Arrange
            var userId = "testuser";
            _mockDatabaseService
                .Setup(x => x.RetrieveSecuritySettingAsync($"2FA_SECRET_{userId}"))
                .ReturnsAsync("SOMEKEY");

            // Act
            var result = await _twoFactorAuthService.IsTwoFactorEnabledAsync(userId);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public async Task IsTwoFactorEnabled_ShouldReturnFalse_WhenKeyDoesNotExist()
        {
            // Arrange
            var userId = "testuser";
            _mockDatabaseService
                .Setup(x => x.RetrieveSecuritySettingAsync($"2FA_SECRET_{userId}"))
                .ReturnsAsync((string)null);

            // Act
            var result = await _twoFactorAuthService.IsTwoFactorEnabledAsync(userId);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public async Task GenerateRecoveryCodes_ShouldGenerateUniqueValidCodes()
        {
            // Arrange
            var userId = "testuser";
            _mockEncryptionService.Setup(x => x.GenerateSalt()).Returns(new byte[16]);
            _mockEncryptionService
                .Setup(x => x.HashPassword(It.IsAny<string>(), It.IsAny<byte[]>()))
                .Returns<string, byte[]>((pwd, _) => pwd);

            // Act
            var codes = await _twoFactorAuthService.GenerateRecoveryCodesAsync(userId);

            // Assert
            Assert.Equal(8, codes.Length); // Default recovery code count
            Assert.True(codes.All(c => c.Length == 10)); // Default recovery code length
            Assert.Equal(codes.Distinct().Count(), codes.Length); // All codes should be unique
            Assert.True(codes.All(c => c.All(ch => char.IsLetterOrDigit(ch)))); // Only alphanumeric characters
        }

        [Fact]
        public async Task ValidateRecoveryCode_ShouldReturnTrue_ForValidCode()
        {
            // Arrange
            var userId = "testuser";
            var validCode = "ABC123DEF4";
            var salt = new byte[16];
            var hashedCode = $"{Convert.ToBase64String(salt)}:{validCode}";

            _mockDatabaseService
                .Setup(x => x.RetrieveSecuritySettingAsync($"2FA_RECOVERY_HASHES_{userId}"))
                .ReturnsAsync(hashedCode);

            _mockEncryptionService.Setup(x => x.HashPassword(validCode, salt)).Returns(validCode);

            // Act
            var result = await _twoFactorAuthService.ValidateRecoveryCodeAsync(userId, validCode);

            // Assert
            Assert.True(result);
            _mockDatabaseService.Verify(
                x => x.UpdateSecuritySettingAsync(
                    $"2FA_RECOVERY_HASHES_{userId}",
                    It.Is<string>(s => s == "")), // Code should be removed after use
                Times.Once);
        }

        [Fact]
        public async Task ValidateRecoveryCode_ShouldReturnFalse_ForInvalidCode()
        {
            // Arrange
            var userId = "testuser";
            var invalidCode = "INVALID123";
            var salt = new byte[16];
            var hashedCode = $"{Convert.ToBase64String(salt)}:DIFFERENTHASH";

            _mockDatabaseService
                .Setup(x => x.RetrieveSecuritySettingAsync($"2FA_RECOVERY_HASHES_{userId}"))
                .ReturnsAsync(hashedCode);

            _mockEncryptionService.Setup(x => x.HashPassword(invalidCode, salt)).Returns(invalidCode);

            // Act
            var result = await _twoFactorAuthService.ValidateRecoveryCodeAsync(userId, invalidCode);

            // Assert
            Assert.False(result);
            _mockDatabaseService.Verify(
                x => x.UpdateSecuritySettingAsync(
                    $"2FA_RECOVERY_HASHES_{userId}",
                    It.IsAny<string>()),
                Times.Never);
        }

        [Fact]
        public async Task InitiateTwoFactorSetup_ShouldReturnValidSetupInfo()
        {
            // Arrange
            var userId = "testuser";
            var user = new User { Id = userId, Username = "testuser@example.com" };

            _mockDatabaseService.Setup(x => x.GetUserAsync(userId)).ReturnsAsync(user);
            _mockEncryptionService.Setup(x => x.GenerateSalt()).Returns(new byte[16]);
            _mockEncryptionService
                .Setup(x => x.HashPassword(It.IsAny<string>(), It.IsAny<byte[]>()))
                .Returns<string, byte[]>((pwd, _) => pwd);

            // Act
            var setupInfo = await _twoFactorAuthService.InitiateTwoFactorSetupAsync(userId);

            // Assert
            Assert.NotNull(setupInfo);
            Assert.NotNull(setupInfo.SecretKey);
            Assert.NotNull(setupInfo.QrCodeUri);
            Assert.NotNull(setupInfo.ManualEntryKey);
            Assert.NotNull(setupInfo.RecoveryCodes);
            Assert.Equal(8, setupInfo.RecoveryCodes.Length);
            Assert.Contains(setupInfo.SecretKey, setupInfo.QrCodeUri);
            Assert.Contains(Uri.EscapeDataString(user.Username), setupInfo.QrCodeUri);
        }
    }
}
