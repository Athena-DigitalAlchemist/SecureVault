using SecureVault.Core.Services;

namespace SecureVault.Tests.Services
{
    [TestClass]
    public class EncryptionServiceTests
    {
        private EncryptionService _encryptionService;

        [TestInitialize]
        public void Setup()
        {
            _encryptionService = new EncryptionService("TestMasterPassword123!");
        }

        [TestMethod]
        public void EncryptDecrypt_ShouldReturnOriginalText()
        {
            // Arrange
            string originalText = "This is a test message!";

            // Act
            string encrypted = _encryptionService.EncryptString(originalText);
            string decrypted = _encryptionService.DecryptString(encrypted);

            // Assert
            Assert.AreEqual(originalText, decrypted);
        }

        [TestMethod]
        public void EncryptString_WithEmptyString_ShouldReturnEmptyString()
        {
            // Arrange
            string emptyText = string.Empty;

            // Act
            string encrypted = _encryptionService.EncryptString(emptyText);

            // Assert
            Assert.AreEqual(string.Empty, encrypted);
        }

        [TestMethod]
        public void DecryptString_WithEmptyString_ShouldReturnEmptyString()
        {
            // Arrange
            string emptyText = string.Empty;

            // Act
            string decrypted = _encryptionService.DecryptString(emptyText);

            // Assert
            Assert.AreEqual(string.Empty, decrypted);
        }

        [TestMethod]
        public void EncryptString_WithNullString_ShouldReturnEmptyString()
        {
            // Arrange
            string nullText = null;

            // Act
            string encrypted = _encryptionService.EncryptString(nullText);

            // Assert
            Assert.AreEqual(string.Empty, encrypted);
        }

        [TestMethod]
        public void DifferentPasswords_ShouldProduceDifferentEncryption()
        {
            // Arrange
            var service1 = new EncryptionService("Password1");
            var service2 = new EncryptionService("Password2");
            string text = "Test message";

            // Act
            string encrypted1 = service1.EncryptString(text);
            string encrypted2 = service2.EncryptString(text);

            // Assert
            Assert.AreNotEqual(encrypted1, encrypted2);
        }
    }
}
