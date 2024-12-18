using Microsoft.Extensions.Logging;
using SecureVault.Core.Exceptions;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;

namespace SecureVault.Core.Services
{
    public class SecureFileStorageService : ISecureFileStorageService
    {
        private readonly IEncryptionService _encryptionService;
        private readonly IDatabaseService _databaseService;
        private readonly IAuditLogService _auditLogService;
        private readonly ILogger<SecureFileStorageService> _logger;
        private readonly string _secureStoragePath;
        private const int BufferSize = 81920; // 80KB chunks

        public SecureFileStorageService(
            IEncryptionService encryptionService,
            IDatabaseService databaseService,
            IAuditLogService auditLogService,
            ILogger<SecureFileStorageService> logger)
        {
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
            _databaseService = databaseService ?? throw new ArgumentNullException(nameof(databaseService));
            _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _secureStoragePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SecureStorage");
            Directory.CreateDirectory(_secureStoragePath);
        }

        public async Task<SecureFile> UploadFileAsync(string userId, string filePath, string encryptionKey)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentNullException(nameof(userId));
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));
            if (string.IsNullOrEmpty(encryptionKey))
                throw new ArgumentNullException(nameof(encryptionKey));

            try
            {
                if (!File.Exists(filePath))
                    throw new FileNotFoundException($"File not found: {filePath}");

                var fileInfo = new FileInfo(filePath);
                var fileName = Path.GetFileName(filePath);
                var encryptedPath = Path.Combine(_secureStoragePath, $"{Guid.NewGuid()}.enc");

                using (var inputStream = File.OpenRead(filePath))
                using (var outputStream = File.Create(encryptedPath))
                {
                    var encryptedStream = await _encryptionService.EncryptStreamAsync(inputStream, encryptionKey);
                    await encryptedStream.CopyToAsync(outputStream);
                }

                var hash = await CalculateFileHashAsync(encryptedPath);

                var secureFile = new SecureFile
                {
                    UserId = userId,
                    FileName = fileName,
                    EncryptedContent = await File.ReadAllBytesAsync(encryptedPath),
                    ContentType = GetContentType(filePath),
                    EncryptedPath = encryptedPath,
                    OriginalPath = filePath,
                    FileSize = fileInfo.Length,
                    CreatedAt = DateTime.UtcNow,
                    LastModified = DateTime.UtcNow,
                    Hash = hash,
                    Description = null,
                    IsShared = false,
                    SharedWith = null,
                    ExpiresAt = null
                };

                var fileId = await _databaseService.SaveSecureFileAsync(secureFile, userId);
                secureFile.Id = fileId;

                await _auditLogService.LogActionAsync(userId, AuditEventType.FileUploaded, $"File uploaded: {fileName}");

                return secureFile;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading file");
                throw;
            }
        }

        public async Task<byte[]> DownloadFileAsync(string fileId, string encryptionKey)
        {
            try
            {
                var secureFile = await _databaseService.GetSecureFileAsync(int.Parse(fileId));
                if (secureFile == null)
                    throw new FileOperationException($"File not found: {fileId}");

                using (var inputStream = File.OpenRead(secureFile.EncryptedPath))
                {
                    var decryptedStream = await _encryptionService.DecryptStreamAsync(inputStream, encryptionKey);
                    using var memoryStream = new MemoryStream();
                    await decryptedStream.CopyToAsync(memoryStream);
                    return memoryStream.ToArray();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error downloading file");
                throw new FileOperationException("Failed to download file", ex);
            }
        }

        public async Task<IEnumerable<SecureFile>> GetUserFilesAsync(string userId)
        {
            try
            {
                return await _databaseService.GetSecureFilesAsync(userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user files");
                throw new DatabaseOperationException("Failed to get user files", ex);
            }
        }

        public async Task<SecureFile> GetFileInfoAsync(string fileId)
        {
            try
            {
                var file = await _databaseService.GetSecureFileAsync(int.Parse(fileId));
                if (file == null)
                    throw new FileOperationException($"File not found: {fileId}");
                return file;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting file info");
                throw new DatabaseOperationException("Failed to get file info", ex);
            }
        }

        public async Task<string> StoreFileAsync(string userId, byte[] fileContent, string fileName)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentNullException(nameof(userId));
            if (fileContent == null)
                throw new ArgumentNullException(nameof(fileContent));
            if (string.IsNullOrEmpty(fileName))
                throw new ArgumentNullException(nameof(fileName));

            try
            {
                var encryptedPath = Path.Combine(_secureStoragePath, $"{Guid.NewGuid()}.enc");
                await File.WriteAllBytesAsync(encryptedPath, fileContent);
                return encryptedPath;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error storing file");
                throw new FileOperationException("Failed to store file", ex);
            }
        }

        public async Task<byte[]> RetrieveFileAsync(string userId, string fileId)
        {
            try
            {
                var secureFile = await GetFileInfoAsync(fileId);
                if (secureFile == null)
                    throw new FileOperationException($"File not found: {fileId}");

                return await File.ReadAllBytesAsync(secureFile.EncryptedPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving file");
                throw new FileOperationException("Failed to retrieve file", ex);
            }
        }

        public async Task DeleteFileAsync(string userId, string fileId)
        {
            try
            {
                var secureFile = await GetFileInfoAsync(fileId);
                if (secureFile == null)
                    throw new FileOperationException($"File not found: {fileId}");

                if (File.Exists(secureFile.EncryptedPath))
                {
                    File.Delete(secureFile.EncryptedPath);
                }

                await _databaseService.DeleteSecureFileAsync(secureFile.Id);
                await _auditLogService.LogActionAsync(AuditEventType.FileDeleted, userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting file");
                throw new FileOperationException("Failed to delete file", ex);
            }
        }

        public async Task<bool> BackupFilesAsync(string userId, string destinationPath)
        {
            try
            {
                var files = await GetUserFilesAsync(userId);
                foreach (var file in files)
                {
                    var backupPath = Path.Combine(destinationPath, Path.GetFileName(file.EncryptedPath));
                    await Task.Run(() => File.Copy(file.EncryptedPath, backupPath, true));
                }

                await _auditLogService.LogActionAsync(AuditEventType.BackupCreated, userId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error backing up files");
                throw new FileOperationException("Failed to backup files", ex);
            }
        }

        public async Task<bool> RestoreFilesAsync(string userId, string sourcePath)
        {
            try
            {
                var files = Directory.GetFiles(sourcePath, "*.enc");
                foreach (var file in files)
                {
                    var restorePath = Path.Combine(_secureStoragePath, Path.GetFileName(file));
                    await Task.Run(() => File.Copy(file, restorePath, true));
                }

                await _auditLogService.LogActionAsync(AuditEventType.BackupRestored, userId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error restoring files");
                throw new FileOperationException("Failed to restore files", ex);
            }
        }

        private string GetContentType(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            return Path.GetExtension(filePath).ToLowerInvariant() switch
            {
                ".txt" => "text/plain",
                ".pdf" => "application/pdf",
                ".doc" => "application/msword",
                ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ".xls" => "application/vnd.ms-excel",
                ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                ".png" => "image/png",
                ".jpg" => "image/jpeg",
                ".jpeg" => "image/jpeg",
                ".gif" => "image/gif",
                _ => "application/octet-stream"
            };
        }

        private async Task<string> CalculateFileHashAsync(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            using var stream = File.OpenRead(filePath);
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hash = await Task.Run(() => sha256.ComputeHash(stream));
            return Convert.ToBase64String(hash);
        }
    }
}
