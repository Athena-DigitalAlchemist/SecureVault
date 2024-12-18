namespace SecureVault.Core.Models
{
    public class SecureNote
    {
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public string EncryptedContent { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string[] Tags { get; set; } = Array.Empty<string>();
        public DateTime CreatedAt { get; set; }
        public DateTime LastModified { get; set; }
        public bool IsFavorite { get; set; }
        public bool IsEncrypted { get; set; }
        public string? EncryptionKeyId { get; set; }
    }
}
