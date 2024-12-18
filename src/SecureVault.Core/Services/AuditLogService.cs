using Microsoft.Extensions.Logging;
using SecureVault.Core.Enums;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;

namespace SecureVault.Core.Services
{
    public class AuditLogService : IAuditLogService
    {
        private readonly IDatabaseService _databaseService;
        private readonly ILogger<AuditLogService> _logger;

        public AuditLogService(IDatabaseService databaseService, ILogger<AuditLogService> logger)
        {
            _databaseService = databaseService;
            _logger = logger;
        }

        public async Task SaveAuditLogAsync(AuditLog log)
        {
            await _databaseService.SaveAuditLogAsync(log);
        }

        public async Task<List<AuditLog>> GetAuditLogsAsync(string userId, int limit = 100)
        {
            return await _databaseService.GetAuditLogsAsync(userId, limit);
        }

        public async Task<bool> ClearAuditLogsAsync(string userId, DateTime before)
        {
            return await _databaseService.ClearAuditLogsAsync(userId, before);
        }

        public async Task<List<AuditLog>> GetAuditLogsAsync(string userId, DateTime startDate, DateTime endDate)
        {
            return await _databaseService.GetAuditLogsAsync(userId, startDate, endDate);
        }

        public async Task<List<AuditLog>> GetAuditLogsByTypeAsync(string userId, AuditEventType type)
        {
            return await _databaseService.GetAuditLogsByTypeAsync(userId, type);
        }

        public async Task LogEventAsync(string userId, AuditEventType eventType, string description)
        {
            var log = new AuditLog
            {
                UserId = userId,
                EventType = eventType,
                Description = description,
                Timestamp = DateTime.UtcNow
            };

            await SaveAuditLogAsync(log);
            _logger.LogInformation($"Audit event logged: {eventType} for user {userId}");
        }

        public async Task LogActionAsync(string userId, AuditEventType eventType, string action, string details = null)
        {
            var description = $"Action: {action}";
            if (!string.IsNullOrEmpty(details))
            {
                description += $" - Details: {details}";
            }

            await LogEventAsync(userId, eventType, description);
        }
    }
}
