using SecureVault.Core.Services;
using static SecureVault.Core.Services.PasswordGeneratorService;

namespace SecureVault.Tests.Services
{
    [TestClass]
    public class PasswordGeneratorServiceTests
    {
        private PasswordGeneratorService _passwordGenerator = null!;

        [TestInitialize]
        public void Setup()
        {
            _passwordGenerator = new PasswordGeneratorService();
        }

        [TestMethod]
        public void GeneratePassword_DefaultSettings_ShouldMeetCriteria()
        {
            // Arrange
            var options = new PasswordOptions
            {
                Length = 16,
                IncludeLowercase = true,
                IncludeUppercase = true,
                IncludeNumbers = true,
                IncludeSpecial = true
            };

            // Act
            string password = _passwordGenerator.GeneratePassword(options);

            // Assert
            Assert.AreEqual(16, password.Length);
            Assert.IsTrue(password.Any(char.IsUpper), "Password should contain uppercase letters");
            Assert.IsTrue(password.Any(char.IsLower), "Password should contain lowercase letters");
            Assert.IsTrue(password.Any(char.IsDigit), "Password should contain numbers");
            Assert.IsTrue(password.Any(c => !char.IsLetterOrDigit(c)), "Password should contain special characters");
        }

        [TestMethod]
        public void GeneratePassword_OnlyLetters_ShouldNotContainOtherCharacters()
        {
            // Arrange
            var options = new PasswordOptions
            {
                Length = 12,
                IncludeLowercase = true,
                IncludeUppercase = true,
                IncludeNumbers = false,
                IncludeSpecial = false
            };

            // Act
            string password = _passwordGenerator.GeneratePassword(options);

            // Assert
            Assert.AreEqual(12, password.Length);
            Assert.IsTrue(password.All(c => char.IsLetter(c)), "Password should only contain letters");
        }

        [TestMethod]
        public void GeneratePassword_OnlyNumbers_ShouldNotContainOtherCharacters()
        {
            // Arrange
            var options = new PasswordOptions
            {
                Length = 8,
                IncludeLowercase = false,
                IncludeUppercase = false,
                IncludeNumbers = true,
                IncludeSpecial = false
            };

            // Act
            string password = _passwordGenerator.GeneratePassword(options);

            // Assert
            Assert.AreEqual(8, password.Length);
            Assert.IsTrue(password.All(char.IsDigit), "Password should only contain numbers");
        }

        [TestMethod]
        public void GeneratePassword_DifferentLengths_ShouldMatchSpecifiedLength()
        {
            // Arrange
            int[] lengths = { 8, 16, 32, 64 };

            foreach (int length in lengths)
            {
                // Act
                var options = new PasswordOptions { Length = length };
                string password = _passwordGenerator.GeneratePassword(options);

                // Assert
                Assert.AreEqual(length, password.Length, $"Password length should be {length}");
            }
        }

        [TestMethod]
        public void CalculatePasswordStrength_StrongPassword_ShouldReturnHigh()
        {
            // Arrange
            string strongPassword = "P@ssw0rd123!";

            // Act
            int strength = (int)_passwordGenerator.CalculatePasswordStrength(strongPassword);

            // Assert
            Assert.IsTrue(strength >= 80, "Strong password should have high strength score");
        }

        [TestMethod]
        public void CalculatePasswordStrength_WeakPassword_ShouldReturnLow()
        {
            // Arrange
            string weakPassword = "password";

            // Act
            int strength = (int)_passwordGenerator.CalculatePasswordStrength(weakPassword);

            // Assert
            Assert.IsTrue(strength <= 40, "Weak password should have low strength score");
        }
    }
}
