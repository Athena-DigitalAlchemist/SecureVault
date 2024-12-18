using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MaterialDesignThemes.Wpf;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;

namespace SecureVault.UI.ViewModels
{
    public partial class DashboardViewModel : ObservableObject
    {
        private readonly IAuthenticationService _authService;
        private readonly IPasswordService _passwordService;
        private readonly ISecureNoteService _noteService;
        private readonly ISecureFileService _fileService;
        private readonly IBackupService _backupService;
        private readonly ILogger<DashboardViewModel> _logger;

        [ObservableProperty]
        private string _welcomeMessage = string.Empty;

        [ObservableProperty]
        private string _lastLoginMessage = string.Empty;

        [ObservableProperty]
        private int _passwordCount;

        [ObservableProperty]
        private int _secureNotesCount;

        [ObservableProperty]
        private int _secureFilesCount;

        [ObservableProperty]
        private string _lastBackupTime = "Never";

        [ObservableProperty]
        private ObservableCollection<RecentItemViewModel> _recentItems = new();

        public ICommand AddPasswordCommand { get; }
        public ICommand AddSecureNoteCommand { get; }
        public ICommand UploadFileCommand { get; }
        public ICommand GeneratePasswordCommand { get; }
        public ICommand OpenItemCommand { get; }

        public DashboardViewModel(
            IAuthenticationService authService,
            IPasswordService passwordService,
            ISecureNoteService noteService,
            ISecureFileService fileService,
            IBackupService backupService,
            ILogger<DashboardViewModel> logger)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _passwordService = passwordService ?? throw new ArgumentNullException(nameof(passwordService));
            _noteService = noteService ?? throw new ArgumentNullException(nameof(noteService));
            _fileService = fileService ?? throw new ArgumentNullException(nameof(fileService));
            _backupService = backupService ?? throw new ArgumentNullException(nameof(backupService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            AddPasswordCommand = new AsyncRelayCommand(AddPasswordAsync);
            AddSecureNoteCommand = new AsyncRelayCommand(AddSecureNoteAsync);
            UploadFileCommand = new AsyncRelayCommand(UploadFileAsync);
            GeneratePasswordCommand = new AsyncRelayCommand(GeneratePasswordAsync);
            OpenItemCommand = new AsyncRelayCommand<RecentItemViewModel>(OpenItemAsync);

            InitializeAsync().FireAndForget();
        }

        private async Task InitializeAsync()
        {
            try
            {
                var user = await _authService.GetCurrentUserAsync();
                WelcomeMessage = $"Welcome back, {user.Username}!";
                LastLoginMessage = $"Last login: {user.LastLoginTime:g}";

                await Task.WhenAll(
                    LoadCountsAsync(),
                    LoadRecentItemsAsync(),
                    LoadLastBackupTimeAsync()
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize dashboard");
            }
        }

        private async Task LoadCountsAsync()
        {
            try
            {
                var userId = await _authService.GetCurrentUserIdAsync();
                PasswordCount = await _passwordService.GetPasswordCountAsync(userId);
                SecureNotesCount = await _noteService.GetNoteCountAsync(userId);
                SecureFilesCount = await _fileService.GetFileCountAsync(userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load counts");
            }
        }

        private async Task LoadRecentItemsAsync()
        {
            try
            {
                RecentItems.Clear();
                var userId = await _authService.GetCurrentUserIdAsync();

                // Load recent passwords
                var recentPasswords = await _passwordService.GetRecentPasswordsAsync(userId, 5);
                foreach (var password in recentPasswords)
                {
                    RecentItems.Add(new RecentItemViewModel
                    {
                        Id = password.Id,
                        Title = password.Title,
                        LastModified = password.LastModified,
                        ItemType = RecentItemType.Password,
                        IconKind = PackIconKind.Key
                    });
                }

                // Load recent notes
                var recentNotes = await _noteService.GetRecentNotesAsync(userId, 5);
                foreach (var note in recentNotes)
                {
                    RecentItems.Add(new RecentItemViewModel
                    {
                        Id = note.Id,
                        Title = note.Title,
                        LastModified = note.LastModified,
                        ItemType = RecentItemType.Note,
                        IconKind = PackIconKind.Note
                    });
                }

                // Load recent files
                var recentFiles = await _fileService.GetRecentFilesAsync(userId, 5);
                foreach (var file in recentFiles)
                {
                    RecentItems.Add(new RecentItemViewModel
                    {
                        Id = file.Id,
                        Title = file.FileName,
                        LastModified = file.LastModified,
                        ItemType = RecentItemType.File,
                        IconKind = PackIconKind.File
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load recent items");
            }
        }

        private async Task LoadLastBackupTimeAsync()
        {
            try
            {
                var lastBackup = await _backupService.GetLastBackupTimeAsync();
                LastBackupTime = lastBackup.HasValue 
                    ? lastBackup.Value.ToString("g") 
                    : "Never";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load last backup time");
            }
        }

        private async Task AddPasswordAsync()
        {
            try
            {
                // Navigate to password add view
                // Implementation depends on your navigation service
                _logger.LogInformation("Navigating to add password view");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to navigate to add password view");
            }
        }

        private async Task AddSecureNoteAsync()
        {
            try
            {
                // Navigate to note add view
                _logger.LogInformation("Navigating to add secure note view");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to navigate to add secure note view");
            }
        }

        private async Task UploadFileAsync()
        {
            try
            {
                // Show file upload dialog
                _logger.LogInformation("Opening file upload dialog");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to open file upload dialog");
            }
        }

        private async Task GeneratePasswordAsync()
        {
            try
            {
                // Show password generator dialog
                _logger.LogInformation("Opening password generator dialog");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to open password generator dialog");
            }
        }

        private async Task OpenItemAsync(RecentItemViewModel? item)
        {
            if (item == null) return;

            try
            {
                // Navigate to appropriate view based on item type
                _logger.LogInformation("Opening recent item: {ItemType} {Title}", 
                    item.ItemType, item.Title);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to open recent item {ItemType} {Title}", 
                    item.ItemType, item.Title);
            }
        }
    }

    public class RecentItemViewModel
    {
        public int Id { get; set; }
        public string Title { get; set; } = string.Empty;
        public DateTime LastModified { get; set; }
        public RecentItemType ItemType { get; set; }
        public PackIconKind IconKind { get; set; }
    }

    public enum RecentItemType
    {
        Password,
        Note,
        File
    }
}
