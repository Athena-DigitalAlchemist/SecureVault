namespace SecureVault.Core.Interfaces
{
    public interface IPasswordHashingService
    {
        Task<string> HashPasswordAsync(string password, string salt);
        Task<string> GenerateSaltAsync();
        Task<bool> VerifyPasswordAsync(string password, string hashedPassword, string salt);
        Task<bool> ValidatePasswordStrengthAsync(string password);
        Task<int> EstimatePasswordStrengthAsync(string password);
    }
}