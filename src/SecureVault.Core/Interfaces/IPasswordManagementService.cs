namespace SecureVault.Core.Interfaces
{
    public interface IPasswordManagementService
    {
        /// <summary>
        /// Generates a secure password based on specified requirements
        /// </summary>
        Task<string> GenerateSecurePasswordAsync(int length = 16, bool includeSpecialChars = true,
            bool includeNumbers = true, bool includeUppercase = true);

        /// <summary>
        /// Validates password strength and returns a score from 0-100
        /// </summary>
        Task<(int score, string[] weaknesses)> ValidatePasswordStrengthAsync(string password);

        /// <summary>
        /// Checks if the password has been previously compromised
        /// </summary>
        Task<bool> IsPasswordCompromisedAsync(string password);

        /// <summary>
        /// Estimates the time it would take to crack the password
        /// </summary>
        Task<string> EstimatePasswordStrengthAsync(string password);
    }
}
