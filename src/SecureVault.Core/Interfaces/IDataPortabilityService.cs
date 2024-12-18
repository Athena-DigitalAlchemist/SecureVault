using SecureVault.Core.Models;

namespace SecureVault.Core.Interfaces
{
    public interface IDataPortabilityService
    {
        Task<string> ExportDataAsync(string userId, ExportOptions options);
        Task<ImportResult> ImportDataAsync(string userId, string importData, string? password = null);
    }
}