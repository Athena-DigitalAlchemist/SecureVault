using System;
using System.Collections.Generic;

namespace SecureVault.Core.Models
{
    public class SecureFile
    {
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string FileType { get; set; } = string.Empty;
        public string ContentType { get; set; } = string.Empty;
        public long Size { get; set; }
        public long FileSize { get; set; }
        public string Hash { get; set; } = string.Empty;
        public string EncryptedPath { get; set; } = string.Empty;
        public byte[] EncryptedContent { get; set; } = Array.Empty<byte>();
        public string OriginalPath { get; set; } = string.Empty;
        public bool IsShared { get; set; }
        public string[] SharedWith { get; set; } = Array.Empty<string>();
        public DateTime? ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastModified { get; set; }
        public DateTime? LastAccessed { get; set; }
        public string? Description { get; set; }
        public string[] Tags { get; set; } = Array.Empty<string>();
        public string? Category { get; set; }
        public bool IsFavorite { get; set; }
        public string? Icon { get; set; }
        public Dictionary<string, string> CustomFields { get; set; } = new Dictionary<string, string>();
        public Dictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>();
        public bool IsEncrypted { get; set; }
        public string? EncryptionKeyId { get; set; }
        public string? Version { get; set; }
        public string? Checksum { get; set; }
        public string? MimeType { get; set; }
        public string? ThumbnailPath { get; set; }
    }
}
