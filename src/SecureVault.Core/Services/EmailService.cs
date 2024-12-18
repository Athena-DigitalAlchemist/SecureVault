using System.Net.Mail;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;

namespace SecureVault.Core.Services
{
    public class EmailService : IEmailService
    {
        private readonly ILogger<EmailService> _logger;
        private readonly SmtpClient _smtpClient;
        private readonly string _fromAddress;
        private const string EmailPattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";

        public EmailService(
            ILogger<EmailService> logger,
            SmtpClient smtpClient,
            string fromAddress)
        {
            _logger = logger;
            _smtpClient = smtpClient;
            _fromAddress = fromAddress;
        }

        public async Task<bool> SendEmailAsync(string to, string subject, string body, bool isHtml = false)
        {
            try
            {
                var message = new MailMessage
                {
                    From = new MailAddress(_fromAddress),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = isHtml
                };
                message.To.Add(new MailAddress(to));

                await _smtpClient.SendMailAsync(message);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {To}", to);
                return false;
            }
        }

        public async Task<bool> SendPasswordResetEmailAsync(string to, string resetToken)
        {
            try
            {
                var subject = "Password Reset Request";
                var body = GetPasswordResetEmailTemplate(resetToken);
                return await SendEmailAsync(to, subject, body, true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send password reset email to {To}", to);
                return false;
            }
        }

        public async Task<bool> SendVerificationEmailAsync(string to, string verificationToken)
        {
            try
            {
                var subject = "Email Verification";
                var body = GetVerificationEmailTemplate(verificationToken);
                return await SendEmailAsync(to, subject, body, true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send verification email to {To}", to);
                return false;
            }
        }

        public async Task<bool> SendBackupNotificationAsync(string to, string backupStatus)
        {
            try
            {
                var subject = "Backup Status Notification";
                var body = GetBackupNotificationTemplate(backupStatus);
                return await SendEmailAsync(to, subject, body, true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send backup notification to {To}", to);
                return false;
            }
        }

        public async Task<bool> SendSecurityAlertAsync(string to, string alertMessage)
        {
            try
            {
                var subject = "Security Alert";
                var body = GetSecurityAlertTemplate(alertMessage);
                return await SendEmailAsync(to, subject, body, true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send security alert to {To}", to);
                return false;
            }
        }

        public async Task<bool> SendWelcomeEmailAsync(string to, string username)
        {
            try
            {
                var subject = "Welcome to SecureVault";
                var body = GetWelcomeEmailTemplate(username);
                return await SendEmailAsync(to, subject, body, true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send welcome email to {To}", to);
                return false;
            }
        }

        public async Task<bool> SendAccountLockedEmailAsync(string to)
        {
            try
            {
                var subject = "Account Locked";
                var body = GetAccountLockedEmailTemplate();
                return await SendEmailAsync(to, subject, body, true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send account locked email to {To}", to);
                return false;
            }
        }

        public async Task<bool> SendPasswordChangedEmailAsync(string to)
        {
            try
            {
                var subject = "Password Changed";
                var body = GetPasswordChangedEmailTemplate();
                return await SendEmailAsync(to, subject, body, true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send password changed email to {To}", to);
                return false;
            }
        }

        public async Task<bool> ValidateEmailAsync(string email)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(email))
                    return false;

                return await Task.FromResult(Regex.IsMatch(email, EmailPattern));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to validate email {Email}", email);
                return false;
            }
        }

        public async Task<bool> UpdateEmailTemplateAsync(string templateName, string content)
        {
            try
            {
                // Store template in database or file system
                // Implementation needed
                throw new NotImplementedException();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update email template {TemplateName}", templateName);
                return false;
            }
        }

        private string GetPasswordResetEmailTemplate(string resetToken)
        {
            return $@"
                <h2>Password Reset Request</h2>
                <p>A password reset has been requested for your account.</p>
                <p>To reset your password, click the link below:</p>
                <p><a href='#'>Reset Password</a></p>
                <p>Token: {resetToken}</p>
                <p>If you did not request this reset, please ignore this email.</p>";
        }

        private string GetVerificationEmailTemplate(string verificationToken)
        {
            return $@"
                <h2>Email Verification</h2>
                <p>Thank you for registering with SecureVault.</p>
                <p>To verify your email address, click the link below:</p>
                <p><a href='#'>Verify Email</a></p>
                <p>Token: {verificationToken}</p>";
        }

        private string GetBackupNotificationTemplate(string status)
        {
            return $@"
                <h2>Backup Status</h2>
                <p>Your backup has completed with the following status:</p>
                <p>{status}</p>";
        }

        private string GetSecurityAlertTemplate(string alertMessage)
        {
            return $@"
                <h2>Security Alert</h2>
                <p>We detected the following security event:</p>
                <p>{alertMessage}</p>";
        }

        private string GetWelcomeEmailTemplate(string username)
        {
            return $@"
                <h2>Welcome to SecureVault</h2>
                <p>Hello {username},</p>
                <p>Thank you for choosing SecureVault for your secure storage needs.</p>
                <p>Get started by:</p>
                <ul>
                    <li>Setting up two-factor authentication</li>
                    <li>Creating your first secure note</li>
                    <li>Adding your passwords</li>
                </ul>";
        }

        private string GetAccountLockedEmailTemplate()
        {
            return @"
                <h2>Account Locked</h2>
                <p>Your account has been locked due to multiple failed login attempts.</p>
                <p>To unlock your account, please reset your password or contact support.</p>";
        }

        private string GetPasswordChangedEmailTemplate()
        {
            return @"
                <h2>Password Changed</h2>
                <p>Your password has been successfully changed.</p>
                <p>If you did not make this change, please contact support immediately.</p>";
        }
    }
}
