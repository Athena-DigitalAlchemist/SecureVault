using System;
using SecureVault.Core.Enums;

namespace SecureVault.Core.Models
{
    public class AuditLog
    {
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public AuditEventType EventType { get; set; }
        public string Details { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string? AdditionalInfo { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        public bool IsSuccess { get; set; }
        public string? ErrorMessage { get; set; }
        public DateTime Timestamp { get; set; }
        public string? AffectedResource { get; set; }
        public string? ResourceType { get; set; }
        public string? Action { get; set; }
        public string? ChangeDescription { get; set; }
        public string? PreviousValue { get; set; }
        public string? NewValue { get; set; }
    }
}
