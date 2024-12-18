using Microsoft.EntityFrameworkCore;
using SecureVault.Core.Models;

namespace SecureVault.Core.Data
{
    public class SecureVaultDbContext : DbContext
    {
        public SecureVaultDbContext(DbContextOptions<SecureVaultDbContext> options)
            : base(options)
        {
        }

        public DbSet<UserProfile> Users { get; set; }
        public DbSet<PasswordEntry> Passwords { get; set; }
        public DbSet<SecuritySetting> SecuritySettings { get; set; }
        public DbSet<SecureNote> Notes { get; set; }
        public DbSet<SecureFile> Files { get; set; }
        public DbSet<BackupMetadata> BackupMetadata { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Users
            modelBuilder.Entity<UserProfile>()
                .HasIndex(u => u.Username)
                .IsUnique();

            // Passwords
            modelBuilder.Entity<PasswordEntry>()
                .HasIndex(p => new { p.UserId, p.Title });

            // Security Settings
            modelBuilder.Entity<SecuritySetting>()
                .HasIndex(s => s.Key)
                .IsUnique();

            // Notes
            modelBuilder.Entity<SecureNote>()
                .HasIndex(n => new { n.UserId, n.Title });

            // Files
            modelBuilder.Entity<SecureFile>()
                .HasIndex(f => new { f.UserId, f.FileName });

            // Backup Metadata
            modelBuilder.Entity<BackupMetadata>()
                .HasIndex(b => new { b.UserId, b.CreatedAt });

            // Audit Logs
            modelBuilder.Entity<AuditLog>()
                .HasIndex(l => new { l.UserId, l.Timestamp });
        }
    }
}