using Microsoft.EntityFrameworkCore;
using SecureVault.Core.Models;

namespace SecureVault.Core.Data
{
    public class SecureVaultContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<PasswordEntry> Passwords { get; set; }
        public DbSet<SecureNote> Notes { get; set; }
        public DbSet<SecureFile> Files { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<BackupMetadata> BackupHistory { get; set; }

        public SecureVaultContext(DbContextOptions<SecureVaultContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Email).IsRequired();
                entity.Property(e => e.PasswordHash).IsRequired();
                entity.Property(e => e.Salt).IsRequired();
            });

            modelBuilder.Entity<PasswordEntry>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Title).IsRequired();
                entity.Property(e => e.Username).IsRequired();
                entity.Property(e => e.EncryptedPassword).IsRequired();
                entity.Property(e => e.CreatedAt).IsRequired();
                entity.Property(e => e.LastModified).IsRequired();
                entity.HasOne<User>().WithMany().HasForeignKey(e => e.UserId);
            });

            modelBuilder.Entity<SecureNote>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Title).IsRequired();
                entity.Property(e => e.EncryptedContent).IsRequired();
                entity.Property(e => e.CreatedAt).IsRequired();
                entity.Property(e => e.LastModified).IsRequired();
                entity.HasOne<User>().WithMany().HasForeignKey(e => e.UserId);
            });

            modelBuilder.Entity<SecureFile>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.FileName).IsRequired();
                entity.Property(e => e.EncryptedPath).IsRequired();
                entity.Property(e => e.FileSize).IsRequired();
                entity.Property(e => e.ContentType).IsRequired();
                entity.Property(e => e.CreatedAt).IsRequired();
                entity.Property(e => e.LastModified).IsRequired();
                entity.Property(e => e.Hash).IsRequired();
                entity.HasOne<User>().WithMany().HasForeignKey(e => e.UserId);
            });

            modelBuilder.Entity<AuditLog>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Action).IsRequired();
                entity.Property(e => e.Details).IsRequired();
                entity.Property(e => e.Timestamp).IsRequired();
                entity.HasOne<User>().WithMany().HasForeignKey(e => e.UserId);
            });

            modelBuilder.Entity<BackupMetadata>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.FileName).IsRequired();
                entity.Property(e => e.EncryptedPath).IsRequired();
                entity.Property(e => e.Size).IsRequired();
                entity.Property(e => e.CreatedAt).IsRequired();
                entity.Property(e => e.Hash).IsRequired();
                entity.HasOne<User>().WithMany().HasForeignKey(e => e.UserId);
            });
        }
    }
}
