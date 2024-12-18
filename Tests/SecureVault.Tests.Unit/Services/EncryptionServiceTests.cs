using System.Text;
using FluentAssertions;
using SecureVault.Core.Services;
using Xunit;

namespace SecureVault.Tests.Unit.Services
{
    public class EncryptionServiceTests
    {
        private readonly EncryptionService _sut;

        public EncryptionServiceTests()
        {
            _sut = new EncryptionService();
        }

        [Fact]
        public void GenerateSalt_ShouldReturnUniqueValues()
        {
            // Act
            var salt1 = _sut.GenerateSalt();
            var salt2 = _sut.GenerateSalt();

            // Assert
            salt1.Should().NotBeEquivalentTo(salt2);
            salt1.Length.Should().BeGreaterThan(0);
        }

        [Theory]
        [InlineData("password123")]
        [InlineData("ComplexP@ssw0rd!")]
        [InlineData("")]
        public void HashPassword_ShouldReturnDifferentHashesForSamePaswordWithDifferentSalts(string password)
        {
            // Arrange
            var salt1 = _sut.GenerateSalt();
            var salt2 = _sut.GenerateSalt();

            // Act
            var hash1 = _sut.HashPassword(password, salt1);
            var hash2 = _sut.HashPassword(password, salt2);

            // Assert
            hash1.Should().NotBe(hash2);
        }

        [Fact]
        public void HashPassword_ShouldReturnSameHashForSamePasswordAndSalt()
        {
            // Arrange
            var password = "testPassword123!";
            var salt = _sut.GenerateSalt();

            // Act
            var hash1 = _sut.HashPassword(password, salt);
            var hash2 = _sut.HashPassword(password, salt);

            // Assert
            hash1.Should().Be(hash2);
        }

        [Fact]
        public void EncryptData_ShouldReturnDifferentValueThanInput()
        {
            // Arrange
            var data = "sensitive data";
            var key = _sut.GenerateEncryptionKey();

            // Act
            var encrypted = _sut.EncryptData(Encoding.UTF8.GetBytes(data), key);

            // Assert
            encrypted.Should().NotBeEquivalentTo(Encoding.UTF8.GetBytes(data));
        }

        [Theory]
        [InlineData("Hello, World!")]
        [InlineData("")]
        [InlineData("Special Ch@racters !@#$%^&*()")]
        public void EncryptAndDecrypt_ShouldReturnOriginalData(string input)
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes(input);
            var key = _sut.GenerateEncryptionKey();

            // Act
            var encrypted = _sut.EncryptData(data, key);
            var decrypted = _sut.DecryptData(encrypted, key);

            // Assert
            decrypted.Should().BeEquivalentTo(data);
            Encoding.UTF8.GetString(decrypted).Should().Be(input);
        }

        [Fact]
        public void DecryptData_WithWrongKey_ShouldThrowException()
        {
            // Arrange
            var data = "sensitive data";
            var correctKey = _sut.GenerateEncryptionKey();
            var wrongKey = _sut.GenerateEncryptionKey();
            var encrypted = _sut.EncryptData(Encoding.UTF8.GetBytes(data), correctKey);

            // Act & Assert
            var act = () => _sut.DecryptData(encrypted, wrongKey);
            act.Should().Throw<Exception>().WithMessage("*decryption failed*");
        }

        [Fact]
        public void GenerateEncryptionKey_ShouldReturnUniqueKeys()
        {
            // Act
            var key1 = _sut.GenerateEncryptionKey();
            var key2 = _sut.GenerateEncryptionKey();

            // Assert
            key1.Should().NotBeEquivalentTo(key2);
        }
    }
}
