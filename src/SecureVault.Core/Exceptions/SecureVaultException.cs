namespace SecureVault.Core.Exceptions
{
    public class SecureVaultException : Exception
    {
        public string ErrorCode { get; }

        public SecureVaultException(string message, string errorCode = "GENERAL_ERROR")
            : base(message)
        {
            ErrorCode = errorCode;
        }

        public SecureVaultException(string message, Exception innerException, string errorCode = "GENERAL_ERROR")
            : base(message, innerException)
        {
            ErrorCode = errorCode;
        }
    }

    public class PasswordValidationException : SecureVaultException
    {
        public PasswordValidationException(string message)
            : base(message, "PASSWORD_VALIDATION_ERROR")
        {
        }

        public PasswordValidationException(string message, Exception innerException)
            : base(message, innerException, "PASSWORD_VALIDATION_ERROR")
        {
        }
    }

    public class DatabaseOperationException : SecureVaultException
    {
        public DatabaseOperationException(string message)
            : base(message, "DATABASE_OPERATION_ERROR")
        {
        }

        public DatabaseOperationException(string message, Exception innerException)
            : base(message, innerException, "DATABASE_OPERATION_ERROR")
        {
        }
    }

    public class FileOperationException : SecureVaultException
    {
        public FileOperationException(string message)
            : base(message, "FILE_OPERATION_ERROR")
        {
        }

        public FileOperationException(string message, Exception innerException)
            : base(message, innerException, "FILE_OPERATION_ERROR")
        {
        }
    }

    public class EncryptionException : SecureVaultException
    {
        public EncryptionException(string message)
            : base(message, "ENCRYPTION_ERROR")
        {
        }

        public EncryptionException(string message, Exception innerException)
            : base(message, innerException, "ENCRYPTION_ERROR")
        {
        }
    }

    public class DecryptionException : SecureVaultException
    {
        public DecryptionException(string message)
            : base(message, "DECRYPTION_ERROR")
        {
        }

        public DecryptionException(string message, Exception innerException)
            : base(message, innerException, "DECRYPTION_ERROR")
        {
        }
    }

    public class PasswordComplexityException : SecureVaultException
    {
        public PasswordComplexityException(string message)
            : base(message, "PASSWORD_COMPLEXITY_ERROR")
        {
        }
    }

    public class SecurityException : SecureVaultException
    {
        public SecurityException(string message)
            : base(message, "SECURITY_ERROR")
        {
        }

        public SecurityException(string message, Exception innerException)
            : base(message, innerException, "SECURITY_ERROR")
        {
        }
    }

    public class AuthenticationException : SecureVaultException
    {
        public AuthenticationException(string message)
            : base(message, "AUTHENTICATION_ERROR")
        {
        }

        public AuthenticationException(string message, Exception innerException)
            : base(message, innerException, "AUTHENTICATION_ERROR")
        {
        }
    }

    public class SessionException : SecureVaultException
    {
        public SessionException(string message)
            : base(message, "SESSION_ERROR")
        {
        }

        public SessionException(string message, Exception innerException)
            : base(message, innerException, "SESSION_ERROR")
        {
        }
    }

    public class BackupException : SecureVaultException
    {
        public BackupException(string message)
            : base(message, "BACKUP_ERROR")
        {
        }

        public BackupException(string message, Exception innerException)
            : base(message, innerException, "BACKUP_ERROR")
        {
        }
    }

    public class DataIntegrityException : SecureVaultException
    {
        public DataIntegrityException(string message)
            : base(message, "DATA_INTEGRITY_ERROR")
        {
        }

        public DataIntegrityException(string message, Exception innerException)
            : base(message, innerException, "DATA_INTEGRITY_ERROR")
        {
        }
    }

    public class KeyManagementException : SecureVaultException
    {
        public KeyManagementException(string message)
            : base(message, "KEY_MANAGEMENT_ERROR")
        {
        }

        public KeyManagementException(string message, Exception innerException)
            : base(message, innerException, "KEY_MANAGEMENT_ERROR")
        {
        }
    }
}