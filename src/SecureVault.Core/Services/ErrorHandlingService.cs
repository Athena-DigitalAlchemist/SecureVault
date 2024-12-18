using SecureVault.Core.Exceptions;
using SecureVault.Core.Interfaces;

namespace SecureVault.Core.Services
{
    public class ErrorHandlingService
    {
        private readonly IAuditLogService _auditLogService;
        private readonly string _systemUserId = "SYSTEM";

        public ErrorHandlingService(IAuditLogService auditLogService)
        {
            _auditLogService = auditLogService;
        }

        public async Task<T> HandleOperationAsync<T>(Func<Task<T>> operation, string operationName)
        {
            try
            {
                return await operation();
            }
            catch (AuthenticationException ex)
            {
                await LogErrorAsync(ex, operationName);
                throw new SecureVaultException(
                    "Authentication failed. Please check your credentials and try again.", ex);
            }
            catch (PasswordValidationException ex)
            {
                await LogErrorAsync(ex, operationName);
                throw new SecureVaultException(
                    "Password validation failed. Please ensure your password meets the required criteria.", ex);
            }
            catch (DatabaseOperationException ex)
            {
                await LogErrorAsync(ex, operationName);
                throw new SecureVaultException(
                    "A database operation error occurred. Please try again later.", ex);
            }
            catch (FileOperationException ex)
            {
                await LogErrorAsync(ex, operationName);
                throw new SecureVaultException(
                    "A file operation error occurred. Please check file permissions and try again.", ex);
            }
            catch (EncryptionException ex)
            {
                await LogErrorAsync(ex, operationName);
                throw new SecureVaultException(
                    "An encryption error occurred. Please ensure your encryption keys are valid.", ex);
            }
            catch (Exception ex)
            {
                await LogErrorAsync(ex, operationName);
                throw new SecureVaultException(
                    "An unexpected error occurred. Please try again or contact support.", ex);
            }
        }

        public async Task HandleOperationAsync(Func<Task> operation, string operationName)
        {
            try
            {
                await operation();
            }
            catch (Exception ex)
            {
                await LogErrorAsync(ex, operationName);
                throw;
            }
        }

        private async Task LogErrorAsync(Exception ex, string operationName)
        {
            var errorMessage = $"Error in {operationName}: {ex.Message}";
            if (ex is SecureVaultException svEx)
            {
                errorMessage += $" (Error Code: {svEx.ErrorCode})";
            }

            await _auditLogService.LogEventAsync(
                _systemUserId,
                AuditEventType.UserLoggedOut,
                $"Error: {ex.Message}"
            );
        }

        public string GetUserFriendlyMessage(Exception ex)
        {
            return ex switch
            {
                AuthenticationException _ =>
                    "Authentication failed. Please check your credentials and try again.",
                PasswordValidationException _ =>
                    "Password validation failed. Please ensure your password meets the required criteria.",
                DatabaseOperationException _ =>
                    "A database error occurred. Please try again later.",
                FileOperationException _ =>
                    "A file operation error occurred. Please check your permissions and try again.",
                EncryptionException _ =>
                    "An encryption error occurred. Please try again later.",
                _ => "An unexpected error occurred. Please try again or contact support."
            };
        }
    }
}
