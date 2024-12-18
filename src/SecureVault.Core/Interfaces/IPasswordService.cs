using SecureVault.Core.Models;

namespace SecureVault.Core.Interfaces
{
    public interface IPasswordService
    {
        Task<PasswordEntry> CreatePasswordAsync(PasswordEntry entry, string masterKey);
        Task<PasswordEntry> GetPasswordAsync(string id, string masterKey);
        Task<IEnumerable<PasswordEntry>> GetAllPasswordsAsync(string userId);
        Task UpdatePasswordAsync(PasswordEntry entry, string masterKey);
        Task DeletePasswordAsync(string id);
        Task<string> GeneratePasswordAsync(
            int length = 16,
            bool includeLowercase = true,
            bool includeUppercase = true,
            bool includeNumbers = true,
            bool includeSpecialChars = true);
    }
}
