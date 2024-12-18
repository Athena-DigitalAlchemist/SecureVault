namespace SecureVault.Core.Models
{
    public class UserSettings
    {
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public bool AutoLockEnabled { get; set; }
        public int AutoLockTimeout { get; set; }
        public bool NotificationsEnabled { get; set; }
        public string Theme { get; set; } = "Light";
        public string Language { get; set; } = "en";
        public bool PasswordGeneratorSettings { get; set; }
        public int DefaultPasswordLength { get; set; } = 16;
        public bool UseSpecialCharacters { get; set; } = true;
        public bool UseNumbers { get; set; } = true;
        public bool UseUppercase { get; set; } = true;
        public DateTime LastModified { get; set; }
    }
}