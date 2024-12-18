using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Win32;
using SecureVault.Core.Models;
using SecureVault.Core.Services;

namespace SecureVault.UI.ViewModels
{
    public class SecureFilesViewModel : ViewModelBase
    {
        private readonly ISecureFileService _fileService;
        private readonly IDialogService _dialogService;
        private readonly IEncryptionService _encryptionService;

        private ObservableCollection<SecureFile> _files;
        private SecureFile _selectedFile;
        private string _searchQuery;
        private string _selectedFileType;
        private bool _isUploading;
        private double _uploadProgress;
        private string _currentFileName;
        private int _totalFiles;
        private int _currentFileIndex;

        public ObservableCollection<SecureFile> Files
        {
            get => _files;
            set => SetProperty(ref _files, value);
        }

        public SecureFile SelectedFile
        {
            get => _selectedFile;
            set => SetProperty(ref _selectedFile, value);
        }

        public string SearchQuery
        {
            get => _searchQuery;
            set
            {
                if (SetProperty(ref _searchQuery, value))
                {
                    FilterFilesAsync();
                }
            }
        }

        public string SelectedFileType
        {
            get => _selectedFileType;
            set
            {
                if (SetProperty(ref _selectedFileType, value))
                {
                    FilterFilesAsync();
                }
            }
        }

        public bool IsUploading
        {
            get => _isUploading;
            set => SetProperty(ref _isUploading, value);
        }

        public double UploadProgress
        {
            get => _uploadProgress;
            set => SetProperty(ref _uploadProgress, value);
        }

        public string CurrentFileName
        {
            get => _currentFileName;
            set => SetProperty(ref _currentFileName, value);
        }

        public string UploadStatus => $"Uploading file {_currentFileIndex} of {_totalFiles}";

        public ObservableCollection<string> FileTypes { get; }

        public ICommand UploadFilesCommand { get; }
        public ICommand CreateFolderCommand { get; }
        public ICommand DownloadFileCommand { get; }
        public ICommand DeleteFileCommand { get; }
        public ICommand SortCommand { get; }

        public SecureFilesViewModel(
            ISecureFileService fileService,
            IDialogService dialogService,
            IEncryptionService encryptionService)
        {
            _fileService = fileService;
            _dialogService = dialogService;
            _encryptionService = encryptionService;

            Files = new ObservableCollection<SecureFile>();
            FileTypes = new ObservableCollection<string>();

            UploadFilesCommand = new RelayCommand(UploadFilesFromDialogAsync);
            CreateFolderCommand = new RelayCommand(CreateFolder);
            DownloadFileCommand = new RelayCommand<SecureFile>(DownloadFileAsync);
            DeleteFileCommand = new RelayCommand<SecureFile>(DeleteFileAsync);
            SortCommand = new RelayCommand(SortFiles);

            LoadFilesAsync();
        }

        private async Task LoadFilesAsync()
        {
            try
            {
                var files = await _fileService.GetAllFilesAsync();
                
                Files.Clear();
                foreach (var file in files)
                {
                    Files.Add(file);
                }

                // Load file types
                var types = files.Select(f => f.FileType)
                                .Where(t => !string.IsNullOrEmpty(t))
                                .Distinct()
                                .OrderBy(t => t);
                
                FileTypes.Clear();
                FileTypes.Add("All");
                foreach (var type in types)
                {
                    FileTypes.Add(type);
                }
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error loading files", ex.Message);
            }
        }

        private async Task UploadFilesAsync(string[] filePaths)
        {
            try
            {
                IsUploading = true;
                _totalFiles = filePaths.Length;
                _currentFileIndex = 0;

                foreach (var filePath in filePaths)
                {
                    _currentFileIndex++;
                    CurrentFileName = System.IO.Path.GetFileName(filePath);
                    UploadProgress = (_currentFileIndex - 1.0) / _totalFiles * 100;

                    var file = await _fileService.UploadFileAsync(filePath);
                    if (file != null)
                    {
                        Files.Add(file);
                    }

                    OnPropertyChanged(nameof(UploadStatus));
                }

                await _dialogService.ShowSuccessAsync("Upload Complete", 
                    $"Successfully uploaded {_totalFiles} file{(_totalFiles > 1 ? "s" : "")}");
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Upload Failed", ex.Message);
            }
            finally
            {
                IsUploading = false;
                UploadProgress = 0;
                CurrentFileName = null;
                _totalFiles = 0;
                _currentFileIndex = 0;
            }
        }

        private async Task UploadFilesFromDialogAsync()
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Multiselect = true,
                Title = "Select Files to Upload"
            };

            if (dialog.ShowDialog() == true)
            {
                await UploadFilesAsync(dialog.FileNames);
            }
        }

        private async void CreateFolder()
        {
            var folderName = await _dialogService.ShowInputDialogAsync(
                "Create Folder",
                "Enter folder name:");

            if (!string.IsNullOrWhiteSpace(folderName))
            {
                try
                {
                    var folder = await _fileService.CreateFolderAsync(folderName);
                    Files.Add(folder);
                }
                catch (Exception ex)
                {
                    await _dialogService.ShowErrorAsync("Error creating folder", ex.Message);
                }
            }
        }

        private async void DownloadFileAsync(SecureFile file)
        {
            if (file == null) return;

            var dialog = new SaveFileDialog
            {
                FileName = file.Name,
                Filter = $"File (*{file.Extension})|*{file.Extension}"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    IsUploading = true; // Reuse the progress UI
                    UploadProgress = 0;
                    UploadStatus = $"Downloading {file.Name}...";

                    var progress = new Progress<double>(p =>
                    {
                        UploadProgress = p;
                    });

                    await _fileService.DownloadFileAsync(file.Id, dialog.FileName, progress);
                    await _dialogService.ShowNotificationAsync("File downloaded successfully");
                }
                catch (Exception ex)
                {
                    await _dialogService.ShowErrorAsync("Error downloading file", ex.Message);
                }
                finally
                {
                    IsUploading = false;
                }
            }
        }

        private async void DeleteFileAsync(SecureFile file)
        {
            if (file == null) return;

            if (await _dialogService.ShowConfirmationAsync(
                "Delete File",
                $"Are you sure you want to delete '{file.Name}'?"))
            {
                try
                {
                    await _fileService.DeleteFileAsync(file.Id);
                    Files.Remove(file);
                }
                catch (Exception ex)
                {
                    await _dialogService.ShowErrorAsync("Error deleting file", ex.Message);
                }
            }
        }

        private void SortFiles()
        {
            var sorted = Files.OrderBy(f => f.Name).ToList();
            Files.Clear();
            foreach (var file in sorted)
            {
                Files.Add(file);
            }
        }

        private async void FilterFilesAsync()
        {
            try
            {
                var allFiles = await _fileService.GetAllFilesAsync();
                var filtered = allFiles.AsEnumerable();

                if (!string.IsNullOrWhiteSpace(SearchQuery))
                {
                    filtered = filtered.Where(f =>
                        f.Name.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase));
                }

                if (!string.IsNullOrWhiteSpace(SelectedFileType) && SelectedFileType != "All")
                {
                    filtered = filtered.Where(f => f.FileType == SelectedFileType);
                }

                Files.Clear();
                foreach (var file in filtered)
                {
                    Files.Add(file);
                }
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error filtering files", ex.Message);
            }
        }
    }
}
