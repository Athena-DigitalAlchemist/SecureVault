-- Users table
CREATE TABLE IF NOT EXISTS Users (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    Username TEXT UNIQUE NOT NULL,
    Email TEXT UNIQUE NOT NULL,
    PasswordHash TEXT NOT NULL,
    Salt TEXT NOT NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    LastLoginAt DATETIME,
    IsTwoFactorEnabled BOOLEAN NOT NULL DEFAULT 0,
    TwoFactorKey TEXT,
    IsLocked BOOLEAN NOT NULL DEFAULT 0,
    FailedLoginAttempts INTEGER NOT NULL DEFAULT 0,
    LockoutEnd DATETIME,
    EmailConfirmed BOOLEAN NOT NULL DEFAULT 0,
    EmailConfirmationToken TEXT
);

-- Two-Factor Authentication table
CREATE TABLE IF NOT EXISTS TwoFactorAuth (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    UserId INTEGER NOT NULL,
    SecretKey TEXT NOT NULL,
    IsEnabled BOOLEAN NOT NULL DEFAULT 0,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    LastUsedAt DATETIME,
    RecoveryEmail TEXT,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Recovery Codes table
CREATE TABLE IF NOT EXISTS RecoveryCodes (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    UserId INTEGER NOT NULL,
    Code TEXT NOT NULL,
    IsUsed BOOLEAN NOT NULL DEFAULT 0,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UsedAt DATETIME,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Password Reset Tokens table
CREATE TABLE IF NOT EXISTS PasswordResetTokens (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    UserId INTEGER NOT NULL,
    Token TEXT NOT NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ExpiresAt DATETIME NOT NULL,
    IsUsed BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Security Settings table
CREATE TABLE IF NOT EXISTS SecuritySettings (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    UserId INTEGER NOT NULL,
    SettingKey TEXT NOT NULL,
    SettingValue TEXT NOT NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME,
    FOREIGN KEY (UserId) REFERENCES Users(Id),
    UNIQUE(UserId, SettingKey)
);

-- Password Entries table
CREATE TABLE IF NOT EXISTS PasswordEntries (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    UserId INTEGER NOT NULL,
    Title TEXT NOT NULL,
    Username TEXT,
    EncryptedPassword TEXT NOT NULL,
    Website TEXT,
    Notes TEXT,
    Category TEXT,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    LastModified DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ExpiryDate DATETIME,
    LastPasswordChange DATETIME,
    Strength INTEGER,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Secure Files table
CREATE TABLE IF NOT EXISTS SecureFiles (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    UserId INTEGER NOT NULL,
    FileName TEXT NOT NULL,
    FileType TEXT NOT NULL,
    OriginalPath TEXT NOT NULL,
    EncryptedPath TEXT NOT NULL,
    FileSize INTEGER NOT NULL,
    ContentType TEXT,
    Hash TEXT NOT NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    LastModified DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Audit Log table
CREATE TABLE IF NOT EXISTS AuditLog (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    UserId INTEGER NOT NULL,
    EventType TEXT NOT NULL,
    EventDescription TEXT NOT NULL,
    IpAddress TEXT,
    UserAgent TEXT,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Backup History table
CREATE TABLE IF NOT EXISTS BackupHistory (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    UserId INTEGER NOT NULL,
    BackupPath TEXT NOT NULL,
    BackupSize INTEGER NOT NULL,
    BackupType TEXT NOT NULL,
    Status TEXT NOT NULL,
    StartedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CompletedAt DATETIME,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Backup Configuration table
CREATE TABLE IF NOT EXISTS BackupConfiguration (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    UserId INTEGER NOT NULL,
    IsEnabled BOOLEAN NOT NULL DEFAULT 0,
    Frequency TEXT NOT NULL,
    RetentionDays INTEGER NOT NULL DEFAULT 30,
    LastBackup DATETIME,
    BackupPath TEXT NOT NULL,
    EncryptionEnabled BOOLEAN NOT NULL DEFAULT 1,
    CompressionEnabled BOOLEAN NOT NULL DEFAULT 1,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON Users(Email);
CREATE INDEX IF NOT EXISTS idx_users_username ON Users(Username);
CREATE INDEX IF NOT EXISTS idx_password_entries_userid ON PasswordEntries(UserId);
CREATE INDEX IF NOT EXISTS idx_secure_files_userid ON SecureFiles(UserId);
CREATE INDEX IF NOT EXISTS idx_audit_log_userid ON AuditLog(UserId);
CREATE INDEX IF NOT EXISTS idx_backup_history_userid ON BackupHistory(UserId);
