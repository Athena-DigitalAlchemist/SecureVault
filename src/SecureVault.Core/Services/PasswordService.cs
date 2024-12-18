using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Exceptions;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;

namespace SecureVault.Core.Services
{
    public class PasswordService : IPasswordService
    {
        private readonly ILogger<PasswordService> _logger;
        private readonly IDatabaseService _databaseService;
        private readonly IEncryptionService _encryptionService;
        private readonly IPasswordHashingService _passwordHashingService;
        private const int MinPasswordLength = 12;
        private const string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
        private const string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string NumberChars = "0123456789";
        private const string SpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

        public PasswordService(
            ILogger<PasswordService> logger,
            IDatabaseService databaseService,
            IEncryptionService encryptionService,
            IPasswordHashingService passwordHashingService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _databaseService = databaseService ?? throw new ArgumentNullException(nameof(databaseService));
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
            _passwordHashingService = passwordHashingService ?? throw new ArgumentNullException(nameof(passwordHashingService));
        }

        public async Task<PasswordEntry> CreatePasswordAsync(PasswordEntry entry, string masterKey)
        {
            if (entry == null)
                throw new ArgumentNullException(nameof(entry));
            if (string.IsNullOrEmpty(masterKey))
                throw new ArgumentNullException(nameof(masterKey));

            try
            {
                // Validate password strength
                if (!await _passwordHashingService.ValidatePasswordStrengthAsync(entry.Password))
                {
                    throw new PasswordValidationException("Password does not meet strength requirements");
                }

                // Encrypt sensitive data
                entry.EncryptedPassword = await _encryptionService.EncryptAsync(entry.Password, masterKey);
                if (!string.IsNullOrEmpty(entry.Notes))
                {
                    entry.EncryptedNotes = await _encryptionService.EncryptAsync(entry.Notes, masterKey);
                }

                // Set metadata
                entry.CreatedAt = DateTime.UtcNow;
                entry.LastModified = DateTime.UtcNow;
                entry.LastAccessed = DateTime.UtcNow;

                // Save to database
                var id = await _databaseService.SavePasswordAsync(entry);
                entry.Id = id;

                _logger.LogInformation("Created new password entry with ID: {Id}", id);
                return entry;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create password entry");
                throw new PasswordValidationException("Failed to create password entry", ex);
            }
        }

        public async Task<PasswordEntry> GetPasswordAsync(string id, string masterKey)
        {
            if (string.IsNullOrEmpty(id))
                throw new ArgumentNullException(nameof(id));
            if (string.IsNullOrEmpty(masterKey))
                throw new ArgumentNullException(nameof(masterKey));

            try
            {
                var entry = await _databaseService.GetPasswordAsync(id);
                if (entry == null)
                {
                    throw new PasswordValidationException($"Password entry not found: {id}");
                }

                // Decrypt sensitive data
                entry.Password = await _encryptionService.DecryptAsync(entry.EncryptedPassword, masterKey);
                if (!string.IsNullOrEmpty(entry.EncryptedNotes))
                {
                    entry.Notes = await _encryptionService.DecryptAsync(entry.EncryptedNotes, masterKey);
                }

                // Update last accessed time
                entry.LastAccessed = DateTime.UtcNow;
                await _databaseService.SavePasswordAsync(entry);

                _logger.LogInformation("Retrieved password entry with ID: {Id}", id);
                return entry;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve password entry: {Id}", id);
                throw new PasswordValidationException($"Failed to retrieve password entry: {id}", ex);
            }
        }

        public async Task<IEnumerable<PasswordEntry>> GetAllPasswordsAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentNullException(nameof(userId));

            try
            {
                var entries = await _databaseService.GetAllPasswordsAsync(userId);
                _logger.LogInformation("Retrieved {Count} password entries for user: {UserId}", entries.Count(), userId);
                return entries;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve password entries for user: {UserId}", userId);
                throw new PasswordValidationException("Failed to retrieve password entries", ex);
            }
        }

        public async Task UpdatePasswordAsync(PasswordEntry entry, string masterKey)
        {
            if (entry == null)
                throw new ArgumentNullException(nameof(entry));
            if (string.IsNullOrEmpty(masterKey))
                throw new ArgumentNullException(nameof(masterKey));

            try
            {
                // Validate password strength if password was changed
                if (!string.IsNullOrEmpty(entry.Password))
                {
                    if (!await _passwordHashingService.ValidatePasswordStrengthAsync(entry.Password))
                    {
                        throw new PasswordValidationException("Password does not meet strength requirements");
                    }
                    entry.EncryptedPassword = await _encryptionService.EncryptAsync(entry.Password, masterKey);
                }

                // Encrypt notes if changed
                if (!string.IsNullOrEmpty(entry.Notes))
                {
                    entry.EncryptedNotes = await _encryptionService.EncryptAsync(entry.Notes, masterKey);
                }

                // Update metadata
                entry.LastModified = DateTime.UtcNow;

                // Save changes
                await _databaseService.SavePasswordAsync(entry);
                _logger.LogInformation("Updated password entry with ID: {Id}", entry.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update password entry: {Id}", entry.Id);
                throw new PasswordValidationException($"Failed to update password entry: {entry.Id}", ex);
            }
        }

        public async Task DeletePasswordAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
                throw new ArgumentNullException(nameof(id));

            try
            {
                var success = await _databaseService.DeletePasswordAsync(id);
                if (!success)
                {
                    throw new PasswordValidationException($"Password entry not found: {id}");
                }
                _logger.LogInformation("Deleted password entry with ID: {Id}", id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete password entry: {Id}", id);
                throw new PasswordValidationException($"Failed to delete password entry: {id}", ex);
            }
        }

        public async Task<string> GeneratePasswordAsync(
            int length = 16,
            bool includeLowercase = true,
            bool includeUppercase = true,
            bool includeNumbers = true,
            bool includeSpecialChars = true)
        {
            if (length < MinPasswordLength)
                throw new ArgumentException($"Password length must be at least {MinPasswordLength} characters", nameof(length));

            if (!includeLowercase && !includeUppercase && !includeNumbers && !includeSpecialChars)
                throw new ArgumentException("At least one character type must be included");

            try
            {
                return GenerateRandomPassword(length, includeLowercase, includeUppercase, includeNumbers, includeSpecialChars);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate password");
                throw new PasswordValidationException("Failed to generate password", ex);
            }
        }

        private string GenerateRandomPassword(int length, bool includeLowercase, bool includeUppercase, bool includeNumbers, bool includeSpecial)
        {
            var chars = new List<string>();
            if (includeLowercase) chars.Add(LowercaseChars);
            if (includeUppercase) chars.Add(UppercaseChars);
            if (includeNumbers) chars.Add(NumberChars);
            if (includeSpecial) chars.Add(SpecialChars);

            if (!chars.Any())
                throw new ArgumentException("At least one character set must be selected");

            var password = new char[length];
            var random = new byte[4];

            // Ensure at least one character from each selected set
            var position = 0;
            foreach (var charSet in chars)
            {
                RandomNumberGenerator.Fill(random);
                password[position++] = charSet[BitConverter.ToInt32(random, 0) % charSet.Length];
            }

            // Fill the rest randomly
            var allChars = string.Join(string.Empty, chars);
            while (position < length)
            {
                RandomNumberGenerator.Fill(random);
                password[position++] = allChars[BitConverter.ToInt32(random, 0) % allChars.Length];
            }

            // Shuffle the result
            for (int i = length - 1; i > 0; i--)
            {
                RandomNumberGenerator.Fill(random);
                int j = BitConverter.ToInt32(random, 0) % (i + 1);
                var temp = password[i];
                password[i] = password[j];
                password[j] = temp;
            }

            return new string(password);
        }
    }
}
