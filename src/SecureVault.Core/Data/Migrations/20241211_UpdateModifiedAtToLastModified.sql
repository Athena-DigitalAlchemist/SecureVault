-- Rename ModifiedAt to LastModified in Notes table
BEGIN TRANSACTION;

-- Add new LastModified column
ALTER TABLE Notes ADD LastModified DATETIME;

-- Copy data from ModifiedAt to LastModified
UPDATE Notes SET LastModified = ModifiedAt;

-- Set default value for LastModified
ALTER TABLE Notes ALTER COLUMN LastModified DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Drop old ModifiedAt column
ALTER TABLE Notes DROP COLUMN ModifiedAt;

-- Update any views or indexes that reference ModifiedAt
IF EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_Notes_ModifiedAt')
BEGIN
    DROP INDEX IX_Notes_ModifiedAt ON Notes;
    CREATE INDEX IX_Notes_LastModified ON Notes(LastModified);
END

-- Verify the changes
IF NOT EXISTS (
    SELECT * FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_NAME = 'Notes' AND COLUMN_NAME = 'LastModified'
)
BEGIN
    ROLLBACK;
    RAISERROR ('Migration failed: LastModified column not found', 16, 1);
    RETURN;
END

IF EXISTS (
    SELECT * FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_NAME = 'Notes' AND COLUMN_NAME = 'ModifiedAt'
)
BEGIN
    ROLLBACK;
    RAISERROR ('Migration failed: ModifiedAt column still exists', 16, 1);
    RETURN;
END

COMMIT;
