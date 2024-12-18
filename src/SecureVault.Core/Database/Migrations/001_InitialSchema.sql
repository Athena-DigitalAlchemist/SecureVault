-- Migration: 001_InitialSchema
-- Description: Initial database schema for SecureVault
-- Created: 2024-12-11

-- Migration Version Table
CREATE TABLE IF NOT EXISTS DatabaseMigrations (
    Version INTEGER PRIMARY KEY,
    Name TEXT NOT NULL,
    AppliedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Core Tables
CREATE TABLE IF NOT EXISTS Users (
    Id TEXT PRIMARY KEY,
    Email TEXT UNIQUE NOT NULL,
    PasswordHash TEXT NOT NULL,
    PasswordSalt TEXT NOT NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    LastLoginAt DATETIME,
    IsLocked BOOLEAN NOT NULL DEFAULT 0,
    LockoutEnd DATETIME,
    FailedLoginAttempts INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS PasswordEntries (
    Id TEXT PRIMARY KEY,
    UserId TEXT NOT NULL,
    Title TEXT NOT NULL,
    Username TEXT,
    EncryptedPassword TEXT NOT NULL,
    Website TEXT,
    Notes TEXT,
    Category TEXT,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    LastModified DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

CREATE TABLE IF NOT EXISTS SecureFiles (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    UserId TEXT NOT NULL,
    FileName TEXT NOT NULL,
    FileType TEXT,
    FileSize INTEGER,
    EncryptedPath TEXT,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    LastModified DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Security Tables
CREATE TABLE IF NOT EXISTS TwoFactorAuth (
    Id TEXT PRIMARY KEY,
    UserId TEXT NOT NULL,
    SecretKey TEXT NOT NULL,
    IsEnabled BOOLEAN NOT NULL DEFAULT 0,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    LastUsedAt DATETIME,
    RecoveryEmail TEXT,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

CREATE TABLE IF NOT EXISTS RecoveryCodes (
    Id TEXT PRIMARY KEY,
    UserId TEXT NOT NULL,
    Code TEXT NOT NULL,
    IsUsed BOOLEAN NOT NULL DEFAULT 0,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UsedAt DATETIME,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

CREATE TABLE IF NOT EXISTS PasswordResetTokens (
    Id TEXT PRIMARY KEY,
    UserId TEXT NOT NULL,
    Token TEXT NOT NULL,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ExpiresAt DATETIME NOT NULL,
    IsUsed BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Settings and Configuration
CREATE TABLE IF NOT EXISTS SecuritySettings (
    UserId TEXT NOT NULL,
    SettingKey TEXT NOT NULL,
    SettingValue TEXT,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (UserId, SettingKey),
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

CREATE TABLE IF NOT EXISTS BackupConfigurations (
    Id TEXT PRIMARY KEY,
    UserId TEXT NOT NULL,
    Interval INTEGER NOT NULL,
    Location TEXT NOT NULL,
    LastBackup DATETIME,
    IsEnabled INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Audit and Logging
CREATE TABLE IF NOT EXISTS AuditLog (
    Id TEXT PRIMARY KEY,
    UserId TEXT,
    EventType TEXT NOT NULL,
    EventDescription TEXT NOT NULL,
    IpAddress TEXT,
    UserAgent TEXT,
    CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserId) REFERENCES Users(Id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON Users(Email);
CREATE INDEX IF NOT EXISTS idx_passwords_userid ON PasswordEntries(UserId);
CREATE INDEX IF NOT EXISTS idx_files_userid ON SecureFiles(UserId);
CREATE INDEX IF NOT EXISTS idx_2fa_userid ON TwoFactorAuth(UserId);
CREATE INDEX IF NOT EXISTS idx_recovery_userid ON RecoveryCodes(UserId);
CREATE INDEX IF NOT EXISTS idx_reset_userid ON PasswordResetTokens(UserId);
CREATE INDEX IF NOT EXISTS idx_reset_token ON PasswordResetTokens(Token);
CREATE INDEX IF NOT EXISTS idx_audit_userid ON AuditLog(UserId);
CREATE INDEX IF NOT EXISTS idx_audit_created ON AuditLog(CreatedAt);

-- Record Migration
INSERT INTO DatabaseMigrations (Version, Name) VALUES (1, '001_InitialSchema');
