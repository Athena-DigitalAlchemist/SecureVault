using System.Text.Json;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;

namespace SecureVault.Core.Services
{
    public class DataPortabilityService : IDataPortabilityService
    {
        private readonly IDatabaseService _databaseService;
        private readonly IEncryptionService _encryptionService;

        public DataPortabilityService(
            IDatabaseService databaseService,
            IEncryptionService encryptionService)
        {
            _databaseService = databaseService ?? throw new ArgumentNullException(nameof(databaseService));
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
        }

        public async Task<string> ExportDataAsync(string userId, ExportOptions options)
        {
            if (string.IsNullOrEmpty(userId)) throw new ArgumentNullException(nameof(userId));
            if (options == null) throw new ArgumentNullException(nameof(options));

            var exportData = new
            {
                Metadata = new
                {
                    ExportDate = DateTime.UtcNow,
                    UserId = userId,
                    Version = "1.0"
                },
                Passwords = options.IncludePasswords ? await _databaseService.GetAllPasswordsAsync(userId) : null,
                Notes = options.IncludeNotes ? await _databaseService.GetAllNotesAsync(userId) : null,
                Files = options.IncludeFiles ? await _databaseService.GetAllSecureFilesAsync(userId) : null,
                Settings = options.IncludeSettings ? await _databaseService.GetUserSettingsAsync(userId) : null
            };

            var jsonString = JsonSerializer.Serialize(exportData, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            if (options.EncryptExport && !string.IsNullOrEmpty(options.ExportPassword))
            {
                var encryptedData = await _encryptionService.EncryptAsync(jsonString, options.ExportPassword);
                jsonString = Convert.ToBase64String(encryptedData);
            }

            if (!string.IsNullOrEmpty(options.ExportPath))
            {
                await File.WriteAllTextAsync(options.ExportPath, jsonString);
            }

            return jsonString;
        }

        public async Task<ImportResult> ImportDataAsync(string userId, string importData, string? password = null)
        {
            if (string.IsNullOrEmpty(userId)) throw new ArgumentNullException(nameof(userId));
            if (string.IsNullOrEmpty(importData)) throw new ArgumentNullException(nameof(importData));

            var result = new ImportResult
            {
                Success = false,
                ImportDate = DateTime.UtcNow
            };

            try
            {
                string jsonData = importData;
                if (password != null)
                {
                    var encryptedBytes = Convert.FromBase64String(importData);
                    var decryptedData = await _encryptionService.DecryptAsync(encryptedBytes, password);
                    jsonData = System.Text.Encoding.UTF8.GetString(decryptedData);
                }

                var importedData = JsonSerializer.Deserialize<dynamic>(jsonData);

                // Import passwords
                if (importedData.Passwords != null)
                {
                    foreach (var password in importedData.Passwords.EnumerateArray())
                    {
                        await _databaseService.AddPasswordAsync(userId, password);
                        result.PasswordsImported++;
                    }
                }

                // Import notes
                if (importedData.Notes != null)
                {
                    foreach (var note in importedData.Notes.EnumerateArray())
                    {
                        await _databaseService.AddNoteAsync(userId, note);
                        result.NotesImported++;
                    }
                }

                // Import files
                if (importedData.Files != null)
                {
                    foreach (var file in importedData.Files.EnumerateArray())
                    {
                        await _databaseService.AddSecureFileAsync(userId, file);
                        result.FilesImported++;
                    }
                }

                // Import settings
                if (importedData.Settings != null)
                {
                    await _databaseService.UpdateUserSettingsAsync(userId, importedData.Settings);
                    result.SettingsImported++;
                }

                result.Success = true;
                result.TotalItemsProcessed = result.PasswordsImported + result.NotesImported +
                                           result.FilesImported + result.SettingsImported;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.Warnings.Add($"Import failed: {ex.Message}");
            }

            return result;
        }
    }
}
