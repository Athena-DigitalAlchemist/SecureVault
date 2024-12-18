using SecureVault.Core.Models;

namespace SecureVault.Core.Interfaces
{
    public interface ISecureFileStorageService
    {
        Task<SecureFile> UploadFileAsync(string userId, string filePath, string encryptionKey);
        Task<byte[]> DownloadFileAsync(string fileId, string encryptionKey);
        Task<IEnumerable<SecureFile>> GetUserFilesAsync(string userId);
        Task<SecureFile> GetFileInfoAsync(string fileId);
        Task<string> StoreFileAsync(string userId, byte[] fileContent, string fileName);
        Task<byte[]> RetrieveFileAsync(string userId, string fileId);
        Task DeleteFileAsync(string userId, string fileId);
        Task<bool> BackupFilesAsync(string userId, string destinationPath);
        Task<bool> RestoreFilesAsync(string userId, string sourcePath);
    }
}
