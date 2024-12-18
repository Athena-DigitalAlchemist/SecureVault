using SecureVault.Core.Interfaces;

namespace SecureVault.Core.Services
{
    public class ApplicationService : IApplicationService
    {
        private readonly IEncryptionService _encryptionService;
        private readonly IDatabaseService _databaseService;
        private readonly IKeyManagementService _keyManagementService;

        public ApplicationService(
            IEncryptionService encryptionService,
            IDatabaseService databaseService,
            IKeyManagementService keyManagementService)
        {
            _encryptionService = encryptionService;
            _databaseService = databaseService;
            _keyManagementService = keyManagementService;
        }

        public async Task InitializeAsync()
        {
            await _databaseService.InitializeDatabaseAsync();
            await _keyManagementService.InitializeKeysAsync();
        }

        public async Task<bool> ValidateMasterPasswordAsync(string masterPassword)
        {
            var verificationData = await _databaseService.GetVerificationDataAsync();
            return await _encryptionService.ValidatePasswordAsync(masterPassword, verificationData);
        }

        public async Task SetupNewVaultAsync(string masterPassword)
        {
            var masterKey = await _keyManagementService.GenerateMasterKeyAsync(masterPassword);
            var newKey = await _keyManagementService.GenerateMasterKeyAsync(masterPassword);
            await _encryptionService.UpdateMasterKeyAsync(masterKey, newKey);

            // Generate a salt for the user
            var salt = Convert.ToBase64String(new byte[32]); // Generate a proper salt
            var passwordHash = await _keyManagementService.DeriveKeyFromPasswordAsync(masterPassword, salt);
            await _databaseService.InitializeNewUserAsync("admin", passwordHash, salt);
        }
    }
}
