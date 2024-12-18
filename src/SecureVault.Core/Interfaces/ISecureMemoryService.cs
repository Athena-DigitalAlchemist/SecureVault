namespace SecureVault.Core.Interfaces
{
    public interface ISecureMemoryService
    {
        Task StoreSecurelyAsync<T>(T data) where T : class;
        Task<T> RetrieveSecurelyAsync<T>(string id) where T : class;
        Task<IEnumerable<T>> RetrieveAllSecurelyAsync<T>() where T : class;
        Task UpdateSecurelyAsync<T>(T data) where T : class;
        Task DeleteSecurelyAsync<T>(string id) where T : class;
        Task ClearSecureMemoryAsync();
        Task<bool> IsMemorySecureAsync();
        Task LockMemoryAsync();
        Task UnlockMemoryAsync(string masterKey);
        Task<bool> VerifyMemoryIntegrityAsync();
    }
}