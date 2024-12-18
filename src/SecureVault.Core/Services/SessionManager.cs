using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace SecureVault.Core.Services
{
    public interface ISessionManager
    {
        Task<string> CreateSessionAsync(string userId);
        Task<bool> ValidateSessionAsync(string sessionId, string userId);
        Task InvalidateSessionAsync(string sessionId);
    }

    public class Session
    {
        public required string UserId { get; set; }
        public DateTime LastActivity { get; set; }
        public required string SecurityStamp { get; set; }
        public bool IsActive => (DateTime.UtcNow - LastActivity).TotalMinutes < 30;
    }

    public class SessionManager : ISessionManager, IDisposable
    {
        private readonly ConcurrentDictionary<string, Session> _sessions = new();
        private readonly Timer _cleanupTimer;
        private readonly ILogger<SessionManager> _logger;
        private bool _disposed;

        public SessionManager(ILogger<SessionManager> logger)
        {
            _logger = logger;
            _cleanupTimer = new Timer(CleanupSessions, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        }

        public async Task<string> CreateSessionAsync(string userId)
        {
            var sessionId = GenerateSessionId();
            var securityStamp = await GenerateSecurityStampAsync();

            var session = new Session
            {
                UserId = userId,
                LastActivity = DateTime.UtcNow,
                SecurityStamp = securityStamp
            };

            _sessions.TryAdd(sessionId, session);
            _logger.LogInformation("Created new session for user {UserId}", userId);

            return sessionId;
        }

        public Task<bool> ValidateSessionAsync(string sessionId, string userId)
        {
            if (_sessions.TryGetValue(sessionId, out var session))
            {
                if (session.UserId == userId && session.IsActive)
                {
                    session.LastActivity = DateTime.UtcNow;
                    return Task.FromResult(true);
                }
            }

            return Task.FromResult(false);
        }

        public Task InvalidateSessionAsync(string sessionId)
        {
            if (_sessions.TryRemove(sessionId, out var session))
            {
                _logger.LogInformation("Invalidated session for user {UserId}", session.UserId);
            }

            return Task.CompletedTask;
        }

        private void CleanupSessions(object? state)
        {
            try
            {
                var expiredSessions = _sessions
                    .Where(kvp => !kvp.Value.IsActive)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (var sessionId in expiredSessions)
                {
                    if (_sessions.TryRemove(sessionId, out var session))
                    {
                        _logger.LogInformation("Cleaned up expired session for user {UserId}", session.UserId);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during session cleanup");
            }
        }

        private static string GenerateSessionId()
        {
            var bytes = new byte[32];
            RandomNumberGenerator.Fill(bytes);
            return Convert.ToBase64String(bytes);
        }

        private static Task<string> GenerateSecurityStampAsync()
        {
            var bytes = new byte[32];
            RandomNumberGenerator.Fill(bytes);
            return Task.FromResult(Convert.ToBase64String(bytes));
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _cleanupTimer.Dispose();
                }
                _disposed = true;
            }
        }
    }
}
