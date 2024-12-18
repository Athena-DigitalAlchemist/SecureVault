namespace SecureVault.Core.Interfaces
{
    public interface IApplicationService
    {
        Task InitializeAsync();
        Task<bool> ValidateMasterPasswordAsync(string masterPassword);
        Task SetupNewVaultAsync(string masterPassword);
    }
}
