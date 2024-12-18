namespace SecureVault.Core.Models
{
    public class PasswordEntry
    {
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string EncryptedPassword { get; set; } = string.Empty;
        public string Website { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string[] Tags { get; set; } = Array.Empty<string>();
        public string Notes { get; set; } = string.Empty;
        public string EncryptedNotes { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime LastModified { get; set; }
        public DateTime? LastAccessed { get; set; }
        public bool IsFavorite { get; set; }
        public int? ExpiryDays { get; set; }
        public string PasswordStrength { get; set; } = string.Empty;
    }
}
