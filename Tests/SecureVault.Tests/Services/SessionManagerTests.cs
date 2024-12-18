using Microsoft.Extensions.Logging;
using Moq;
using SecureVault.Core.Services;

namespace SecureVault.Tests.Services
{
    [TestClass]
    public class SessionManagerTests
    {
        private Mock<ILogger<SessionManager>> _loggerMock;
        private SessionManager _sessionManager;

        [TestInitialize]
        public void Setup()
        {
            _loggerMock = new Mock<ILogger<SessionManager>>();
            _sessionManager = new SessionManager(_loggerMock.Object);
        }

        [TestMethod]
        public async Task CreateSessionAsync_ShouldCreateValidSession()
        {
            // Arrange
            var userId = "testUser";

            // Act
            var sessionId = await _sessionManager.CreateSessionAsync(userId);

            // Assert
            Assert.IsNotNull(sessionId);
            var isValid = await _sessionManager.ValidateSessionAsync(sessionId, userId);
            Assert.IsTrue(isValid);
        }

        [TestMethod]
        public async Task ValidateSessionAsync_WithInvalidSessionId_ReturnsFalse()
        {
            // Arrange
            var invalidSessionId = "invalid-session";
            var userId = "testUser";

            // Act
            var isValid = await _sessionManager.ValidateSessionAsync(invalidSessionId, userId);

            // Assert
            Assert.IsFalse(isValid);
        }

        [TestMethod]
        public async Task ValidateSessionAsync_WithWrongUserId_ReturnsFalse()
        {
            // Arrange
            var userId = "testUser";
            var wrongUserId = "wrongUser";
            var sessionId = await _sessionManager.CreateSessionAsync(userId);

            // Act
            var isValid = await _sessionManager.ValidateSessionAsync(sessionId, wrongUserId);

            // Assert
            Assert.IsFalse(isValid);
        }

        [TestMethod]
        public async Task InvalidateSessionAsync_ShouldInvalidateExistingSession()
        {
            // Arrange
            var userId = "testUser";
            var sessionId = await _sessionManager.CreateSessionAsync(userId);

            // Act
            await _sessionManager.InvalidateSessionAsync(sessionId);

            // Assert
            var isValid = await _sessionManager.ValidateSessionAsync(sessionId, userId);
            Assert.IsFalse(isValid);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _sessionManager.Dispose();
        }
    }
}
