using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace SecureVault.Api.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class StorageController : ControllerBase
    {
        private readonly ISecureFileStorageService _storageService;
        private readonly ILogger<StorageController> _logger;

        public StorageController(
            ISecureFileStorageService storageService,
            ILogger<StorageController> logger)
        {
            _storageService = storageService;
            _logger = logger;
        }

        [HttpPost("upload")]
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            try
            {
                if (file == null || file.Length == 0)
                {
                    return BadRequest("No file uploaded");
                }

                var userId = User.Identity.Name;
                var tempPath = Path.GetTempFileName();

                try
                {
                    using (var stream = new FileStream(tempPath, FileMode.Create))
                    {
                        await file.CopyToAsync(stream);
                    }

                    var secureFile = await _storageService.StoreFileAsync(tempPath, userId);
                    return Ok(new { fileId = secureFile.Id });
                }
                finally
                {
                    if (System.IO.File.Exists(tempPath))
                    {
                        System.IO.File.Delete(tempPath);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading file");
                return StatusCode(500, "An error occurred while uploading the file");
            }
        }

        [HttpGet("files")]
        public async Task<ActionResult<IEnumerable<SecureFile>>> ListFiles()
        {
            try
            {
                var userId = User.Identity.Name;
                var files = await _storageService.ListFilesAsync(userId);
                return Ok(files);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error listing files");
                return StatusCode(500, "An error occurred while listing files");
            }
        }

        [HttpGet("files/{fileId}")]
        public async Task<IActionResult> DownloadFile(string fileId)
        {
            try
            {
                var userId = User.Identity.Name;
                var file = await _storageService.GetFileInfoAsync(fileId, userId);
                
                if (file == null)
                {
                    return NotFound();
                }

                var tempPath = Path.GetTempFileName();
                try
                {
                    var filePath = await _storageService.RetrieveFileAsync(file, tempPath);
                    var fileBytes = await System.IO.File.ReadAllBytesAsync(filePath);
                    return File(fileBytes, file.ContentType, file.FileName);
                }
                finally
                {
                    if (System.IO.File.Exists(tempPath))
                    {
                        System.IO.File.Delete(tempPath);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error downloading file");
                return StatusCode(500, "An error occurred while downloading the file");
            }
        }

        [HttpDelete("files/{fileId}")]
        public async Task<IActionResult> DeleteFile(string fileId)
        {
            try
            {
                var userId = User.Identity.Name;
                var file = await _storageService.GetFileInfoAsync(fileId, userId);
                
                if (file == null)
                {
                    return NotFound();
                }

                var success = await _storageService.DeleteFileAsync(file);
                if (!success)
                {
                    return StatusCode(500, "Failed to delete file");
                }

                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting file");
                return StatusCode(500, "An error occurred while deleting the file");
            }
        }

        [HttpPost("backup")]
        public async Task<IActionResult> CreateBackup([FromBody] BackupRequest request)
        {
            try
            {
                var userId = User.Identity.Name;
                var success = await _storageService.BackupFilesAsync(userId, request.DestinationPath);
                
                if (!success)
                {
                    return StatusCode(500, "Failed to create backup");
                }

                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating backup");
                return StatusCode(500, "An error occurred while creating backup");
            }
        }

        [HttpPost("restore")]
        public async Task<IActionResult> RestoreBackup([FromBody] RestoreRequest request)
        {
            try
            {
                var userId = User.Identity.Name;
                var success = await _storageService.RestoreFilesAsync(userId, request.SourcePath);
                
                if (!success)
                {
                    return StatusCode(500, "Failed to restore backup");
                }

                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error restoring backup");
                return StatusCode(500, "An error occurred while restoring backup");
            }
        }
    }

    public class BackupRequest
    {
        public string DestinationPath { get; set; }
    }

    public class RestoreRequest
    {
        public string SourcePath { get; set; }
    }
}
