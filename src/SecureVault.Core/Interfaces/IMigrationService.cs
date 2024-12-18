namespace SecureVault.Core.Interfaces
{
    public interface IMigrationService
    {
        Task<bool> InitializeDatabaseAsync();
        Task<bool> MigrateToLatestVersionAsync();
        Task<bool> BackupDatabaseAsync(string path);
        Task<bool> RestoreDatabaseAsync(string path);
        Task<bool> ValidateDatabaseIntegrityAsync();
        Task<string> GetCurrentVersionAsync();
        Task<List<string>> GetAvailableMigrationsAsync();
        Task<bool> ApplyMigrationAsync(string version);
        Task<bool> RollbackMigrationAsync(string version);
        Task<Dictionary<string, bool>> GetMigrationHistoryAsync();
    }
}
