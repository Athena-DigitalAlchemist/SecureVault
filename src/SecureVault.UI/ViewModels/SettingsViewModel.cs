using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Win32;
using SecureVault.Core.Models;
using SecureVault.Core.Services;

namespace SecureVault.UI.ViewModels
{
    public class SettingsViewModel : ViewModelBase
    {
        private readonly ISettingsService _settingsService;
        private readonly ISecurityService _securityService;
        private readonly IBackupService _backupService;
        private readonly IDialogService _dialogService;
        private readonly IPasswordBreachService _breachService;

        // Security Settings
        private bool _requireUppercase;
        private bool _requireLowercase;
        private bool _requireNumbers;
        private bool _requireSpecialChars;
        private int _minPasswordLength;
        private string _selectedAutoLockTime;

        // Encryption Settings
        private string _selectedEncryptionAlgorithm;
        private string _selectedKeyRotationInterval;

        // Backup Settings
        private bool _enableAutoBackup;
        private string _selectedBackupInterval;
        private string _backupLocation;

        // Security Check Settings
        private bool _enableBreachMonitoring;

        #region Properties

        // Security Settings
        public bool RequireUppercase
        {
            get => _requireUppercase;
            set
            {
                if (SetProperty(ref _requireUppercase, value))
                {
                    SaveSettingsAsync();
                }
            }
        }

        public bool RequireLowercase
        {
            get => _requireLowercase;
            set
            {
                if (SetProperty(ref _requireLowercase, value))
                {
                    SaveSettingsAsync();
                }
            }
        }

        public bool RequireNumbers
        {
            get => _requireNumbers;
            set
            {
                if (SetProperty(ref _requireNumbers, value))
                {
                    SaveSettingsAsync();
                }
            }
        }

        public bool RequireSpecialChars
        {
            get => _requireSpecialChars;
            set
            {
                if (SetProperty(ref _requireSpecialChars, value))
                {
                    SaveSettingsAsync();
                }
            }
        }

        public int MinPasswordLength
        {
            get => _minPasswordLength;
            set
            {
                if (SetProperty(ref _minPasswordLength, value))
                {
                    SaveSettingsAsync();
                }
            }
        }

        public string SelectedAutoLockTime
        {
            get => _selectedAutoLockTime;
            set
            {
                if (SetProperty(ref _selectedAutoLockTime, value))
                {
                    SaveSettingsAsync();
                }
            }
        }

        // Encryption Settings
        public string SelectedEncryptionAlgorithm
        {
            get => _selectedEncryptionAlgorithm;
            set
            {
                if (SetProperty(ref _selectedEncryptionAlgorithm, value))
                {
                    SaveSettingsAsync();
                }
            }
        }

        public string SelectedKeyRotationInterval
        {
            get => _selectedKeyRotationInterval;
            set
            {
                if (SetProperty(ref _selectedKeyRotationInterval, value))
                {
                    SaveSettingsAsync();
                }
            }
        }

        // Backup Settings
        public bool EnableAutoBackup
        {
            get => _enableAutoBackup;
            set
            {
                if (SetProperty(ref _enableAutoBackup, value))
                {
                    SaveSettingsAsync();
                }
            }
        }

        public string SelectedBackupInterval
        {
            get => _selectedBackupInterval;
            set
            {
                if (SetProperty(ref _selectedBackupInterval, value))
                {
                    SaveSettingsAsync();
                }
            }
        }

        public string BackupLocation
        {
            get => _backupLocation;
            set => SetProperty(ref _backupLocation, value);
        }

        // Security Check Settings
        public bool EnableBreachMonitoring
        {
            get => _enableBreachMonitoring;
            set
            {
                if (SetProperty(ref _enableBreachMonitoring, value))
                {
                    SaveSettingsAsync();
                }
            }
        }

        // Collections
        public ObservableCollection<string> AutoLockTimes { get; }
        public ObservableCollection<string> EncryptionAlgorithms { get; }
        public ObservableCollection<string> KeyRotationIntervals { get; }
        public ObservableCollection<string> BackupIntervals { get; }

        #endregion

        #region Commands

        public ICommand ChangeMasterPasswordCommand { get; }
        public ICommand SelectBackupLocationCommand { get; }
        public ICommand CreateBackupCommand { get; }
        public ICommand CheckPasswordsCommand { get; }

        #endregion

        public SettingsViewModel(
            ISettingsService settingsService,
            ISecurityService securityService,
            IBackupService backupService,
            IDialogService dialogService,
            IPasswordBreachService breachService)
        {
            _settingsService = settingsService;
            _securityService = securityService;
            _backupService = backupService;
            _dialogService = dialogService;
            _breachService = breachService;

            // Initialize collections
            AutoLockTimes = new ObservableCollection<string>
            {
                "1 minute",
                "5 minutes",
                "15 minutes",
                "30 minutes",
                "1 hour",
                "Never"
            };

            EncryptionAlgorithms = new ObservableCollection<string>
            {
                "AES-256",
                "ChaCha20-Poly1305"
            };

            KeyRotationIntervals = new ObservableCollection<string>
            {
                "30 days",
                "60 days",
                "90 days",
                "180 days"
            };

            BackupIntervals = new ObservableCollection<string>
            {
                "Daily",
                "Weekly",
                "Monthly"
            };

            // Initialize commands
            ChangeMasterPasswordCommand = new RelayCommand(ChangeMasterPasswordAsync);
            SelectBackupLocationCommand = new RelayCommand(SelectBackupLocation);
            CreateBackupCommand = new RelayCommand(CreateBackupAsync);
            CheckPasswordsCommand = new RelayCommand(CheckPasswordsAsync);

            LoadSettingsAsync();
        }

        private async Task LoadSettingsAsync()
        {
            try
            {
                var settings = await _settingsService.GetSettingsAsync();

                // Security Settings
                RequireUppercase = settings.RequireUppercase;
                RequireLowercase = settings.RequireLowercase;
                RequireNumbers = settings.RequireNumbers;
                RequireSpecialChars = settings.RequireSpecialChars;
                MinPasswordLength = settings.MinPasswordLength;
                SelectedAutoLockTime = settings.AutoLockTime;

                // Encryption Settings
                SelectedEncryptionAlgorithm = settings.EncryptionAlgorithm;
                SelectedKeyRotationInterval = settings.KeyRotationInterval;

                // Backup Settings
                EnableAutoBackup = settings.EnableAutoBackup;
                SelectedBackupInterval = settings.BackupInterval;
                BackupLocation = settings.BackupLocation;

                // Security Check Settings
                EnableBreachMonitoring = settings.EnableBreachMonitoring;
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error loading settings", ex.Message);
            }
        }

        private async Task SaveSettingsAsync()
        {
            try
            {
                var settings = new AppSettings
                {
                    RequireUppercase = RequireUppercase,
                    RequireLowercase = RequireLowercase,
                    RequireNumbers = RequireNumbers,
                    RequireSpecialChars = RequireSpecialChars,
                    MinPasswordLength = MinPasswordLength,
                    AutoLockTime = SelectedAutoLockTime,
                    EncryptionAlgorithm = SelectedEncryptionAlgorithm,
                    KeyRotationInterval = SelectedKeyRotationInterval,
                    EnableAutoBackup = EnableAutoBackup,
                    BackupInterval = SelectedBackupInterval,
                    BackupLocation = BackupLocation,
                    EnableBreachMonitoring = EnableBreachMonitoring
                };

                await _settingsService.SaveSettingsAsync(settings);
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error saving settings", ex.Message);
            }
        }

        private async void ChangeMasterPasswordAsync()
        {
            var viewModel = new ChangeMasterPasswordViewModel(_securityService);
            await _dialogService.ShowDialogAsync(viewModel);
        }

        private void SelectBackupLocation()
        {
            var dialog = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = "Select Backup Location"
            };

            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                BackupLocation = dialog.SelectedPath;
                SaveSettingsAsync();
            }
        }

        private async void CreateBackupAsync()
        {
            try
            {
                await _backupService.CreateBackupAsync(BackupLocation);
                await _dialogService.ShowNotificationAsync("Backup created successfully");
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error creating backup", ex.Message);
            }
        }

        private async void CheckPasswordsAsync()
        {
            try
            {
                var results = await _breachService.CheckPasswordsAsync();
                if (results.Any())
                {
                    var viewModel = new PasswordBreachViewModel(results);
                    await _dialogService.ShowDialogAsync(viewModel);
                }
                else
                {
                    await _dialogService.ShowNotificationAsync("No compromised passwords found!");
                }
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error checking passwords", ex.Message);
            }
        }
    }
}
