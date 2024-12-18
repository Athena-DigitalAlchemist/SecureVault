using Moq;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Services;
using Xunit;

namespace SecureVault.Tests.Services
{
    public class PasswordManagementServiceTests
    {
        private readonly Mock<IAuditLogService> _mockAuditLogService;
        private readonly PasswordManagementService _passwordManagementService;

        public PasswordManagementServiceTests()
        {
            _mockAuditLogService = new Mock<IAuditLogService>();
            _passwordManagementService = new PasswordManagementService(_mockAuditLogService.Object);
        }

        [Theory]
        [InlineData(16, true, true, true)]
        [InlineData(8, false, false, false)]
        [InlineData(32, true, false, true)]
        public async Task GenerateSecurePasswordAsync_ShouldGenerateValidPassword(
            int length, bool includeSpecialChars, bool includeNumbers, bool includeUppercase)
        {
            // Act
            var password = await _passwordManagementService.GenerateSecurePasswordAsync(
                length, includeSpecialChars, includeNumbers, includeUppercase);

            // Assert
            Assert.NotNull(password);
            Assert.Equal(length, password.Length);

            if (includeSpecialChars)
                Assert.Contains(password, c => !char.IsLetterOrDigit(c));
            if (includeNumbers)
                Assert.Contains(password, char.IsDigit);
            if (includeUppercase)
                Assert.Contains(password, char.IsUpper);

            _mockAuditLogService.Verify(x =>
                x.LogEventAsync(It.IsAny<string>(), It.IsAny<string>()), Times.Once);
        }

        [Theory]
        [InlineData("weak", 30)]
        [InlineData("Password123", 60)]
        [InlineData("P@ssw0rd123!@#", 90)]
        public async Task ValidatePasswordStrengthAsync_ShouldReturnCorrectScore(string password, int expectedMinScore)
        {
            // Act
            var (score, weaknesses) = await _passwordManagementService.ValidatePasswordStrengthAsync(password);

            // Assert
            Assert.True(score >= expectedMinScore);
            Assert.NotNull(weaknesses);
        }

        [Fact]
        public async Task ValidatePasswordStrengthAsync_WithEmptyPassword_ShouldReturnZeroScore()
        {
            // Act
            var (score, weaknesses) = await _passwordManagementService.ValidatePasswordStrengthAsync(string.Empty);

            // Assert
            Assert.Equal(0, score);
            Assert.Single(weaknesses);
            Assert.Contains(weaknesses, w => w == "Password cannot be empty");
        }

        [Theory]
        [InlineData("password")]
        [InlineData("123456")]
        [InlineData("qwerty")]
        public async Task IsPasswordCompromisedAsync_ShouldIdentifyCommonPasswords(string password)
        {
            // Act
            var isCompromised = await _passwordManagementService.IsPasswordCompromisedAsync(password);

            // Assert
            Assert.True(isCompromised);
            _mockAuditLogService.Verify(x =>
                x.LogEventAsync(It.IsAny<string>(), It.IsAny<string>()), Times.Once);
        }

        [Theory]
        [InlineData("aB1!")]  // Very short
        [InlineData("abcdefgh")]  // Only lowercase
        [InlineData("ABCDEFGH")]  // Only uppercase
        [InlineData("12345678")]  // Only numbers
        [InlineData("!@#$%^&*")]  // Only special characters
        public async Task EstimatePasswordStrengthAsync_ShouldIdentifyWeakPasswords(string password)
        {
            // Act
            var estimate = await _passwordManagementService.EstimatePasswordStrengthAsync(password);

            // Assert
            Assert.Contains("Less than", estimate, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("P@ssw0rd123!@#$%^")]  // Complex password
        public async Task EstimatePasswordStrengthAsync_ShouldIdentifyStrongPasswords(string password)
        {
            // Act
            var estimate = await _passwordManagementService.EstimatePasswordStrengthAsync(password);

            // Assert
            Assert.DoesNotContain("Less than", estimate, StringComparison.OrdinalIgnoreCase);
        }
    }
}
