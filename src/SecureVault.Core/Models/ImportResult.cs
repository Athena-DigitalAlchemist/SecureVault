namespace SecureVault.Core.Models
{
    public class ImportResult
    {
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public int TotalItemsProcessed { get; set; }
        public int PasswordsImported { get; set; }
        public int NotesImported { get; set; }
        public int FilesImported { get; set; }
        public int SettingsImported { get; set; }
        public int FailedItems { get; set; }
        public List<string> Warnings { get; set; } = new List<string>();
        public DateTime ImportDate { get; set; } = DateTime.UtcNow;
        public string? ImportFilePath { get; set; }
        public string? ImportFormat { get; set; }
    }
}