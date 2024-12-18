using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;
using SecureVault.Core.Services;
using Xunit;

namespace SecureVault.Tests.Unit.Services
{
    public class AuthenticationServiceTests
    {
        private readonly Mock<IDatabaseService> _dbServiceMock;
        private readonly Mock<IEncryptionService> _encryptionServiceMock;
        private readonly Mock<ITwoFactorAuthService> _twoFactorServiceMock;
        private readonly Mock<ILogger<AuthenticationService>> _loggerMock;
        private readonly AuthenticationService _sut;

        public AuthenticationServiceTests()
        {
            _dbServiceMock = new Mock<IDatabaseService>();
            _encryptionServiceMock = new Mock<IEncryptionService>();
            _twoFactorServiceMock = new Mock<ITwoFactorAuthService>();
            _loggerMock = new Mock<ILogger<AuthenticationService>>();

            _sut = new AuthenticationService(
                _dbServiceMock.Object,
                _encryptionServiceMock.Object,
                _twoFactorServiceMock.Object,
                _loggerMock.Object
            );
        }

        [Fact]
        public async Task Login_WithValidCredentials_ShouldReturnSuccess()
        {
            // Arrange
            var username = "testuser";
            var password = "Password123!";
            var salt = new byte[] { 1, 2, 3 };
            var hashedPassword = new byte[] { 4, 5, 6 };

            var user = new User
            {
                Username = username,
                PasswordHash = hashedPassword,
                PasswordSalt = salt,
                IsLocked = false,
                FailedLoginAttempts = 0
            };

            _dbServiceMock.Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync(user);

            _encryptionServiceMock.Setup(x => x.HashPassword(password, salt))
                .Returns(hashedPassword);

            // Act
            var result = await _sut.LoginAsync(username, password);

            // Assert
            result.Success.Should().BeTrue();
            result.RequiresTwoFactor.Should().BeFalse();
            result.ErrorMessage.Should().BeNull();
        }

        [Fact]
        public async Task Login_WithInvalidPassword_ShouldReturnFailure()
        {
            // Arrange
            var username = "testuser";
            var password = "WrongPassword123!";
            var salt = new byte[] { 1, 2, 3 };
            var correctHash = new byte[] { 4, 5, 6 };
            var wrongHash = new byte[] { 7, 8, 9 };

            var user = new User
            {
                Username = username,
                PasswordHash = correctHash,
                PasswordSalt = salt,
                IsLocked = false,
                FailedLoginAttempts = 0
            };

            _dbServiceMock.Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync(user);

            _encryptionServiceMock.Setup(x => x.HashPassword(password, salt))
                .Returns(wrongHash);

            // Act
            var result = await _sut.LoginAsync(username, password);

            // Assert
            result.Success.Should().BeFalse();
            result.ErrorMessage.Should().Contain("Invalid username or password");
        }

        [Fact]
        public async Task Login_WithLockedAccount_ShouldReturnFailure()
        {
            // Arrange
            var username = "testuser";
            var password = "Password123!";
            
            var user = new User
            {
                Username = username,
                IsLocked = true,
                FailedLoginAttempts = 5
            };

            _dbServiceMock.Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync(user);

            // Act
            var result = await _sut.LoginAsync(username, password);

            // Assert
            result.Success.Should().BeFalse();
            result.ErrorMessage.Should().Contain("Account is locked");
        }

        [Fact]
        public async Task Login_WithNonexistentUser_ShouldReturnFailure()
        {
            // Arrange
            var username = "nonexistent";
            var password = "Password123!";

            _dbServiceMock.Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync((User)null);

            // Act
            var result = await _sut.LoginAsync(username, password);

            // Assert
            result.Success.Should().BeFalse();
            result.ErrorMessage.Should().Contain("Invalid username or password");
        }

        [Fact]
        public async Task Login_WithTwoFactorEnabled_ShouldRequireTwoFactor()
        {
            // Arrange
            var username = "testuser";
            var password = "Password123!";
            var salt = new byte[] { 1, 2, 3 };
            var hashedPassword = new byte[] { 4, 5, 6 };

            var user = new User
            {
                Username = username,
                PasswordHash = hashedPassword,
                PasswordSalt = salt,
                IsLocked = false,
                FailedLoginAttempts = 0,
                TwoFactorEnabled = true
            };

            _dbServiceMock.Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync(user);

            _encryptionServiceMock.Setup(x => x.HashPassword(password, salt))
                .Returns(hashedPassword);

            // Act
            var result = await _sut.LoginAsync(username, password);

            // Assert
            result.Success.Should().BeTrue();
            result.RequiresTwoFactor.Should().BeTrue();
        }
    }
}
