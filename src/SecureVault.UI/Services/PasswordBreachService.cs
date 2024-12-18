using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SecureVault.Core.Models;

namespace SecureVault.Core.Services
{
    public interface IPasswordBreachService
    {
        Task<IEnumerable<PasswordBreachResult>> CheckPasswordsAsync();
        Task<bool> IsPasswordBreachedAsync(string password);
        Task<BreachScanResult> ScanCredentialsAsync();
    }

    public class PasswordBreachService : IPasswordBreachService
    {
        private readonly IPasswordService _passwordService;
        private readonly HttpClient _httpClient;
        private const string HibpApiUrl = "https://api.pwnedpasswords.com/range/";

        public PasswordBreachService(IPasswordService passwordService)
        {
            _passwordService = passwordService;
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "SecureVault-PasswordManager");
        }

        public async Task<IEnumerable<PasswordBreachResult>> CheckPasswordsAsync()
        {
            var results = new List<PasswordBreachResult>();
            var passwords = await _passwordService.GetAllPasswordsAsync();

            foreach (var password in passwords)
            {
                try
                {
                    using var securePassword = await _passwordService.GetDecryptedPasswordAsync(password.Id);
                    bool isBreached = await IsPasswordBreachedAsync(securePassword.ToString());

                    if (isBreached)
                    {
                        results.Add(new PasswordBreachResult
                        {
                            PasswordId = password.Id,
                            Title = password.Title,
                            Username = password.Username,
                            LastModified = password.LastModified,
                            BreachType = "Password found in data breach"
                        });
                    }
                }
                catch (Exception ex)
                {
                    // Log the error but continue checking other passwords
                    // TODO: Add proper logging
                    Console.WriteLine($"Error checking password {password.Id}: {ex.Message}");
                }
            }

            return results;
        }

        public async Task<bool> IsPasswordBreachedAsync(string password)
        {
            // Use SHA-1 hash as per HIBP API requirements
            using var sha1 = SHA1.Create();
            var hashBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(password));
            var hash = BitConverter.ToString(hashBytes).Replace("-", "");

            // Send only first 5 characters of hash to API (k-anonymity)
            var prefix = hash.Substring(0, 5);
            var suffix = hash.Substring(5);

            try
            {
                var response = await _httpClient.GetStringAsync($"{HibpApiUrl}{prefix}");
                var hashes = response.Split('\n');

                foreach (var line in hashes)
                {
                    var parts = line.Split(':');
                    if (parts.Length == 2 && parts[0].Trim().Equals(suffix, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                // Log the error
                // TODO: Add proper logging
                Console.WriteLine($"Error checking HIBP API: {ex.Message}");
                throw new Exception("Unable to check password breach status", ex);
            }
        }

        public async Task<BreachScanResult> ScanCredentialsAsync()
        {
            var result = new BreachScanResult
            {
                ScanDate = DateTime.UtcNow,
                CompromisedPasswords = new List<PasswordBreachResult>(),
                TotalPasswordsChecked = 0
            };

            try
            {
                var passwords = await _passwordService.GetAllPasswordsAsync();
                result.TotalPasswordsChecked = passwords.Count;

                foreach (var password in passwords)
                {
                    try
                    {
                        using var securePassword = await _passwordService.GetDecryptedPasswordAsync(password.Id);
                        bool isBreached = await IsPasswordBreachedAsync(securePassword.ToString());

                        if (isBreached)
                        {
                            result.CompromisedPasswords.Add(new PasswordBreachResult
                            {
                                PasswordId = password.Id,
                                Title = password.Title,
                                Username = password.Username,
                                LastModified = password.LastModified,
                                BreachType = "Password found in data breach"
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log individual password check errors but continue scanning
                        result.Errors.Add($"Error checking password {password.Id}: {ex.Message}");
                    }
                }

                result.IsSuccess = true;
            }
            catch (Exception ex)
            {
                result.IsSuccess = false;
                result.Errors.Add($"Scan failed: {ex.Message}");
            }

            return result;
        }
    }

    public class BreachScanResult
    {
        public DateTime ScanDate { get; set; }
        public bool IsSuccess { get; set; }
        public int TotalPasswordsChecked { get; set; }
        public List<PasswordBreachResult> CompromisedPasswords { get; set; } = new List<PasswordBreachResult>();
        public List<string> Errors { get; set; } = new List<string>();
    }

    public class PasswordBreachResult
    {
        public string PasswordId { get; set; }
        public string Title { get; set; }
        public string Username { get; set; }
        public DateTime LastModified { get; set; }
        public string BreachType { get; set; }
    }
}
