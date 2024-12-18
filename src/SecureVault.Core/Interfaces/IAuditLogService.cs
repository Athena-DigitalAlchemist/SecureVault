using SecureVault.Core.Models;
using SecureVault.Core.Enums;

namespace SecureVault.Core.Interfaces
{
    public interface IAuditLogService
    {
        Task SaveAuditLogAsync(AuditLog log);
        Task<List<AuditLog>> GetAuditLogsAsync(string userId, int limit = 100);
        Task<List<AuditLog>> GetAuditLogsAsync(string userId, DateTime startDate, DateTime endDate);
        Task<List<AuditLog>> GetAuditLogsByTypeAsync(string userId, AuditEventType type);
        Task<bool> ClearAuditLogsAsync(string userId, DateTime before);
        Task LogEventAsync(string userId, AuditEventType eventType, string description);
        Task LogActionAsync(string userId, AuditEventType eventType, string action, string details = null);
    }
}
