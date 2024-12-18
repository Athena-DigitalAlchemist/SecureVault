using System.Threading.Tasks;
using Moq;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;
using SecureVault.Core.Services;
using Xunit;

namespace SecureVault.Tests.Unit.Services
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

        [Fact]
        public async Task GenerateSecurePassword_ShouldGenerateValidPassword()
        {
            // Act
            var password = await _passwordManagementService.GenerateSecurePasswordAsync(16, true, true, true);

            // Assert
            Assert.Equal(16, password.Length);
            Assert.Contains(password, c => char.IsUpper(c));
            Assert.Contains(password, c => char.IsLower(c));
            Assert.Contains(password, c => char.IsDigit(c));
            Assert.Contains(password, c => !char.IsLetterOrDigit(c));

            _mockAuditLogService.Verify(x => x.LogEventAsync(
                It.IsAny<string>(),
                AuditEventType.PasswordGenerated,
                It.IsAny<string>()
            ), Times.Once);
        }

        [Theory]
        [InlineData("weak", 0)]
        [InlineData("password123", 60)]
        [InlineData("Password123!", 90)]
        [InlineData("SuperStr0ng!P@ssw0rd", 100)]
        public async Task ValidatePasswordStrength_ShouldReturnCorrectScore(string password, int expectedMinScore)
        {
            // Act
            var (score, weaknesses) = await _passwordManagementService.ValidatePasswordStrengthAsync(password);

            // Assert
            Assert.True(score >= expectedMinScore);
            
            if (score < 100)
            {
                Assert.NotEmpty(weaknesses);
            }

            _mockAuditLogService.Verify(x => x.LogEventAsync(
                It.IsAny<string>(),
                AuditEventType.PasswordValidated,
                It.IsAny<string>()
            ), Times.Once);
        }

        [Theory]
        [InlineData("password", true)]
        [InlineData("123456", true)]
        [InlineData("qwerty", true)]
        [InlineData("SuperStr0ng!P@ssw0rd", false)]
        public async Task IsPasswordCompromised_ShouldIdentifyCompromisedPasswords(string password, bool expectedResult)
        {
            // Act
            var isCompromised = await _passwordManagementService.IsPasswordCompromisedAsync(password);

            // Assert
            Assert.Equal(expectedResult, isCompromised);

            _mockAuditLogService.Verify(x => x.LogEventAsync(
                It.IsAny<string>(),
                AuditEventType.PasswordChecked,
                It.IsAny<string>()
            ), Times.Once);
        }

        [Theory]
        [InlineData("a")]
        [InlineData("abc")]
        [InlineData("abcdef")]
        public async Task EstimatePasswordStrength_ShouldReturnEstimate_ForWeakPasswords(string password)
        {
            // Act
            var estimate = await _passwordManagementService.EstimatePasswordStrengthAsync(password);

            // Assert
            Assert.Contains("minute", estimate.ToLower());
        }

        [Theory]
        [InlineData("SuperStr0ng!P@ssw0rd")]
        [InlineData("VeryL0ng&C0mpl3x!P@ssw0rd")]
        public async Task EstimatePasswordStrength_ShouldReturnEstimate_ForStrongPasswords(string password)
        {
            // Act
            var estimate = await _passwordManagementService.EstimatePasswordStrengthAsync(password);

            // Assert
            Assert.Contains("year", estimate.ToLower());
        }

        [Theory]
        [InlineData("aaa123", true)]  // Contains repeating 'aaa'
        [InlineData("abc123", false)] // No repeating characters
        [InlineData("111abc", true)]  // Contains repeating '111'
        public async Task ValidatePasswordStrength_ShouldDetectRepeatingCharacters(string password, bool hasRepeating)
        {
            // Act
            var (score, weaknesses) = await _passwordManagementService.ValidatePasswordStrengthAsync(password);

            // Assert
            if (hasRepeating)
            {
                Assert.Contains(weaknesses, w => w.Contains("repeating characters"));
                Assert.True(score < 100);
            }
            else
            {
                Assert.DoesNotContain(weaknesses, w => w.Contains("repeating characters"));
            }
        }

        [Theory]
        [InlineData(8)]
        [InlineData(12)]
        [InlineData(16)]
        [InlineData(20)]
        public async Task GenerateSecurePassword_ShouldRespectLengthParameter(int length)
        {
            // Act
            var password = await _passwordManagementService.GenerateSecurePasswordAsync(length);

            // Assert
            Assert.Equal(length, password.Length);
        }

        [Fact]
        public async Task GenerateSecurePassword_WithoutSpecialChars_ShouldNotContainSpecialChars()
        {
            // Act
            var password = await _passwordManagementService.GenerateSecurePasswordAsync(
                length: 16,
                includeSpecialChars: false,
                includeNumbers: true,
                includeUppercase: true);

            // Assert
            Assert.DoesNotContain(password, c => !char.IsLetterOrDigit(c));
            Assert.Contains(password, c => char.IsUpper(c));
            Assert.Contains(password, c => char.IsDigit(c));
        }

        [Fact]
        public async Task GenerateSecurePassword_WithoutNumbers_ShouldNotContainNumbers()
        {
            // Act
            var password = await _passwordManagementService.GenerateSecurePasswordAsync(
                length: 16,
                includeSpecialChars: true,
                includeNumbers: false,
                includeUppercase: true);

            // Assert
            Assert.DoesNotContain(password, char.IsDigit);
            Assert.Contains(password, c => char.IsUpper(c));
            Assert.Contains(password, c => !char.IsLetterOrDigit(c));
        }
    }
}
