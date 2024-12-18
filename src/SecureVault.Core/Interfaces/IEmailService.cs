namespace SecureVault.Core.Interfaces
{
    public interface IEmailService
    {
        Task<bool> SendEmailAsync(string to, string subject, string body, bool isHtml = false);
        Task<bool> SendPasswordResetEmailAsync(string to, string resetToken);
        Task<bool> SendVerificationEmailAsync(string to, string verificationToken);
        Task<bool> SendBackupNotificationAsync(string to, string backupStatus);
        Task<bool> SendSecurityAlertAsync(string to, string alertMessage);
        Task<bool> SendWelcomeEmailAsync(string to, string username);
        Task<bool> SendAccountLockedEmailAsync(string to);
        Task<bool> SendPasswordChangedEmailAsync(string to);
        Task<bool> ValidateEmailAsync(string email);
        Task<bool> UpdateEmailTemplateAsync(string templateName, string content);
    }
}
