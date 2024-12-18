using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;

namespace SecureVault.Tests.Integration
{
    [TestFixture]
    public class AuthenticationTests
    {
        private TestWebApplicationFactory _factory;
        private HttpClient _client;
        private IDatabaseService _dbService;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            _factory = new TestWebApplicationFactory();
        }

        [SetUp]
        public async Task SetUp()
        {
            _client = _factory.CreateClient();
            _dbService = _factory.Services.GetRequiredService<IDatabaseService>();

            // Ensure database is clean
            await _dbService.InitializeDatabaseAsync();
        }

        [Test]
        public async Task Register_WithValidData_ShouldSucceed()
        {
            // Arrange
            var registerData = new
            {
                Username = "testuser",
                Password = "TestPassword123!",
                Email = "test@example.com"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/account/register", registerData);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var user = await _dbService.GetUserByUsernameAsync("testuser");
            user.Should().NotBeNull();
            user.Email.Should().Be("test@example.com");
        }

        [Test]
        public async Task Register_WithExistingUsername_ShouldFail()
        {
            // Arrange
            var registerData = new
            {
                Username = "existinguser",
                Password = "TestPassword123!",
                Email = "test@example.com"
            };

            // Create existing user
            await _client.PostAsJsonAsync("/api/account/register", registerData);

            // Act
            var response = await _client.PostAsJsonAsync("/api/account/register", registerData);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            var error = await response.Content.ReadAsStringAsync();
            error.Should().Contain("Username already exists");
        }

        [Test]
        public async Task Login_WithValidCredentials_ShouldSucceed()
        {
            // Arrange
            var userData = new
            {
                Username = "logintest",
                Password = "TestPassword123!",
                Email = "login@example.com"
            };

            await _client.PostAsJsonAsync("/api/account/register", userData);

            var loginData = new
            {
                Username = userData.Username,
                Password = userData.Password
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/account/login", loginData);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            response.Headers.Should().ContainKey("Set-Cookie");
        }

        [Test]
        public async Task Login_WithInvalidCredentials_ShouldFail()
        {
            // Arrange
            var loginData = new
            {
                Username = "nonexistent",
                Password = "WrongPassword123!"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/account/login", loginData);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Test]
        public async Task ForgotPassword_WithValidEmail_ShouldSucceed()
        {
            // Arrange
            var registerData = new
            {
                Username = "resetuser",
                Password = "TestPassword123!",
                Email = "reset@example.com"
            };

            await _client.PostAsJsonAsync("/api/account/register", registerData);

            var forgotPasswordData = new
            {
                Email = registerData.Email
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/account/forgot-password", forgotPasswordData);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            
            // Verify token was created
            var user = await _dbService.GetUserByEmailAsync(registerData.Email);
            var resetToken = await _dbService.GetPasswordResetTokenAsync(user.Id);
            resetToken.Should().NotBeNull();
        }

        [TearDown]
        public void TearDown()
        {
            _client.Dispose();
        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {
            _factory.Dispose();
        }
    }
}
