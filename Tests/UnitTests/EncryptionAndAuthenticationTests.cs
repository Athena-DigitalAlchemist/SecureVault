using System;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;
using SecureVault.Core.Services;

namespace SecureVault.Tests.UnitTests
{
    [TestClass]
    public class EncryptionAndAuthenticationTests
    {
        private IEncryptionService _encryptionService;
        private Mock<IDatabaseService> _mockDatabaseService;
        private IAuthenticationService _authService;
        private const string TestMasterKey = "TestMasterKey123!@#";
        private readonly byte[] _testSalt = Encoding.UTF8.GetBytes("TestSalt123!@#");

        [TestInitialize]
        public void Setup()
        {
            _encryptionService = new EncryptionService(TestMasterKey, _testSalt);
            _mockDatabaseService = new Mock<IDatabaseService>();
            _authService = new AuthenticationService(_encryptionService, _mockDatabaseService.Object);
        }

        [TestMethod]
        public async Task EncryptDecrypt_ShouldReturnOriginalText()
        {
            // Arrange
            const string plainText = "Test secret message";

            // Act
            var encrypted = await _encryptionService.EncryptAsync(plainText);
            var decrypted = await _encryptionService.DecryptAsync(encrypted);

            // Assert
            Assert.AreEqual(plainText, decrypted);
        }

        [TestMethod]
        public async Task HashPassword_WithSameSalt_ShouldProduceSameHash()
        {
            // Arrange
            const string password = "TestPassword123!@#";
            var salt = await _encryptionService.GenerateSaltAsync();

            // Act
            var hash1 = await _encryptionService.HashPasswordAsync(password, salt);
            var hash2 = await _encryptionService.HashPasswordAsync(password, salt);

            // Assert
            Assert.AreEqual(hash1, hash2);
        }

        [TestMethod]
        public async Task HashPassword_WithDifferentSalt_ShouldProduceDifferentHash()
        {
            // Arrange
            const string password = "TestPassword123!@#";

            // Act
            var hash1 = await _encryptionService.HashPasswordAsync(password);
            var hash2 = await _encryptionService.HashPasswordAsync(password);

            // Assert
            Assert.AreNotEqual(hash1, hash2);
        }

        [TestMethod]
        public async Task UpdateMasterKey_ShouldAllowEncryptionWithNewKey()
        {
            // Arrange
            const string plainText = "Test secret message";
            const string newMasterKey = "NewMasterKey123!@#";

            // Act - Encrypt with old key
            var encrypted = await _encryptionService.EncryptAsync(plainText);

            // Update master key
            await _encryptionService.UpdateMasterKeyAsync(newMasterKey);

            // Try to decrypt with new key
            var decrypted = await _encryptionService.DecryptAsync(encrypted);

            // Assert
            Assert.AreEqual(plainText, decrypted);
        }

        [TestMethod]
        public async Task VerifyPassword_WithValidPassword_ShouldReturnTrue()
        {
            // Arrange
            const string userId = "testUser";
            const string password = "TestPassword123!@#";
            var salt = await _encryptionService.GenerateSaltAsync();
            var hashedPassword = await _encryptionService.HashPasswordAsync(password, salt);

            _mockDatabaseService.Setup(x => x.GetVerificationDataAsync(userId))
                .ReturnsAsync(new VerificationData
                {
                    UserId = userId,
                    PasswordHash = hashedPassword,
                    Salt = Convert.ToBase64String(salt)
                });

            // Act
            var result = await _authService.AuthenticateAsync(password);

            // Assert
            Assert.IsTrue(result);
        }

        [TestMethod]
        public async Task VerifyPassword_WithInvalidPassword_ShouldReturnFalse()
        {
            // Arrange
            const string userId = "testUser";
            const string correctPassword = "TestPassword123!@#";
            const string wrongPassword = "WrongPassword123!@#";
            var salt = await _encryptionService.GenerateSaltAsync();
            var hashedPassword = await _encryptionService.HashPasswordAsync(correctPassword, salt);

            _mockDatabaseService.Setup(x => x.GetVerificationDataAsync(userId))
                .ReturnsAsync(new VerificationData
                {
                    UserId = userId,
                    PasswordHash = hashedPassword,
                    Salt = Convert.ToBase64String(salt)
                });

            // Act
            var result = await _authService.AuthenticateAsync(wrongPassword);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public async Task HashPassword_WithEmptyPassword_ShouldThrowException()
        {
            // Act
            await _encryptionService.HashPasswordAsync(string.Empty);
        }

        [TestMethod]
        public async Task GenerateSalt_ShouldProduceUniqueSalts()
        {
            // Act
            var salt1 = await _encryptionService.GenerateSaltAsync();
            var salt2 = await _encryptionService.GenerateSaltAsync();

            // Assert
            CollectionAssert.AreNotEqual(salt1, salt2);
        }

        [TestMethod]
        public async Task GenerateSalt_ShouldProduceCorrectLength()
        {
            // Arrange
            const int expectedLength = 32;

            // Act
            var salt = await _encryptionService.GenerateSaltAsync(expectedLength);

            // Assert
            Assert.AreEqual(expectedLength, salt.Length);
        }
    }
}
