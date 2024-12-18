namespace SecureVault.Core.Interfaces
{
    public interface IHashingService
    {
        Task<string> HashPasswordAsync(string password, string salt);
        Task<string> GenerateSaltAsync();
        Task<bool> VerifyPasswordAsync(string password, string hash, string salt);
        Task<string> HashDataAsync(byte[] data);
        Task<string> HashFileAsync(string filePath);
    }
}
