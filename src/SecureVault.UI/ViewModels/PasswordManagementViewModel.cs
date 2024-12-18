using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows.Input;
using System.Linq;
using System.Windows;
using System.Collections.Generic;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Models;
using SecureVault.UI.Commands;
using SecureVault.UI.Services;

namespace SecureVault.UI.ViewModels
{
    public class PasswordManagementViewModel : ViewModelBase
    {
        private readonly IPasswordManagementService _passwordManagementService;
        private readonly IDatabaseService _databaseService;
        private readonly INotificationService _notificationService;
        private readonly ICommand _generatePasswordCommand;
        private readonly ICommand _savePasswordCommand;
        private readonly ICommand _deletePasswordCommand;
        private readonly ICommand _copyPasswordCommand;
        private readonly ICommand _addNewEntryCommand;
        private string _generatedPassword;
        private string _passwordStrength;
        private string _searchText;
        private string _selectedCategory;
        private ObservableCollection<PasswordEntry> _passwordEntries;
        private ObservableCollection<PasswordEntry> _filteredEntries;
        private PasswordEntry _selectedEntry;
        private bool _isEditing;

        public PasswordManagementViewModel(
            IPasswordManagementService passwordManagementService,
            IDatabaseService databaseService,
            INotificationService notificationService)
        {
            _passwordManagementService = passwordManagementService;
            _databaseService = databaseService;
            _notificationService = notificationService;
            
            _generatePasswordCommand = new AsyncRelayCommand(GeneratePasswordAsync);
            _savePasswordCommand = new AsyncRelayCommand(SavePasswordEntryAsync, CanSavePassword);
            _deletePasswordCommand = new AsyncRelayCommand(DeletePasswordEntryAsync, CanDeletePassword);
            _copyPasswordCommand = new RelayCommand<string>(CopyToClipboard);
            _addNewEntryCommand = new RelayCommand(AddNewEntry);
            
            _passwordEntries = new ObservableCollection<PasswordEntry>();
            _filteredEntries = new ObservableCollection<PasswordEntry>();
            Categories = new ObservableCollection<string>();

            LoadPasswordEntriesAsync().ConfigureAwait(false);
        }

        public string GeneratedPassword
        {
            get => _generatedPassword;
            set
            {
                if (SetProperty(ref _generatedPassword, value))
                {
                    UpdatePasswordStrengthAsync().ConfigureAwait(false);
                }
            }
        }

        public string SearchText
        {
            get => _searchText;
            set
            {
                if (SetProperty(ref _searchText, value))
                {
                    FilterEntries();
                }
            }
        }

        public string SelectedCategory
        {
            get => _selectedCategory;
            set
            {
                if (SetProperty(ref _selectedCategory, value))
                {
                    FilterEntries();
                }
            }
        }

        public ObservableCollection<string> Categories { get; }

        public string PasswordStrength
        {
            get => _passwordStrength;
            set => SetProperty(ref _passwordStrength, value);
        }

        public ObservableCollection<PasswordEntry> FilteredEntries
        {
            get => _filteredEntries;
            set => SetProperty(ref _filteredEntries, value);
        }

        public PasswordEntry SelectedEntry
        {
            get => _selectedEntry;
            set
            {
                if (SetProperty(ref _selectedEntry, value))
                {
                    IsEditing = value != null;
                }
            }
        }

        public bool IsEditing
        {
            get => _isEditing;
            set => SetProperty(ref _isEditing, value);
        }

        public ICommand GeneratePasswordCommand => _generatePasswordCommand;
        public ICommand SavePasswordCommand => _savePasswordCommand;
        public ICommand DeletePasswordCommand => _deletePasswordCommand;
        public ICommand CopyPasswordCommand => _copyPasswordCommand;
        public ICommand AddNewEntryCommand => _addNewEntryCommand;

        private void FilterEntries()
        {
            var query = _passwordEntries.AsQueryable();

            if (!string.IsNullOrWhiteSpace(SearchText))
            {
                query = query.Where(e =>
                    e.Title.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    e.Username.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    e.Website.Contains(SearchText, StringComparison.OrdinalIgnoreCase));
            }

            if (!string.IsNullOrWhiteSpace(SelectedCategory))
            {
                query = query.Where(e => e.Category == SelectedCategory);
            }

            FilteredEntries = new ObservableCollection<PasswordEntry>(query);
        }

        private void CopyToClipboard(string text)
        {
            if (string.IsNullOrEmpty(text)) return;

            try
            {
                Clipboard.SetText(text);
                _notificationService.ShowSuccessAsync("Copied to clipboard!").ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _notificationService.ShowErrorAsync($"Failed to copy: {ex.Message}").ConfigureAwait(false);
            }
        }

        private void AddNewEntry()
        {
            var newEntry = new PasswordEntry
            {
                Id = Guid.NewGuid().ToString(),
                Title = "New Entry",
                CreatedAt = DateTime.UtcNow,
                LastModified = DateTime.UtcNow
            };

            _passwordEntries.Add(newEntry);
            FilteredEntries.Add(newEntry);
            SelectedEntry = newEntry;
            IsEditing = true;
        }

        private async Task GeneratePasswordAsync()
        {
            try
            {
                GeneratedPassword = await _passwordManagementService.GenerateSecurePasswordAsync();
                await UpdatePasswordStrengthAsync();
                await _notificationService.ShowSuccessAsync("Password generated successfully!");
            }
            catch (Exception ex)
            {
                await _notificationService.ShowErrorAsync($"Error generating password: {ex.Message}");
            }
        }

        private async Task UpdatePasswordStrengthAsync()
        {
            if (string.IsNullOrEmpty(GeneratedPassword))
            {
                PasswordStrength = string.Empty;
                return;
            }

            try
            {
                var (score, weaknesses) = await _passwordManagementService.ValidatePasswordStrengthAsync(GeneratedPassword);
                var timeToBreak = await _passwordManagementService.EstimatePasswordStrengthAsync(GeneratedPassword);
                PasswordStrength = $"Strength: {score}% - Time to crack: {timeToBreak}";

                if (weaknesses.Any())
                {
                    await _notificationService.ShowWarningAsync(
                        $"Password weaknesses found:\n{string.Join("\n", weaknesses)}");
                }
            }
            catch (Exception ex)
            {
                PasswordStrength = "Error calculating password strength";
                await _notificationService.ShowErrorAsync($"Error calculating password strength: {ex.Message}");
            }
        }

        private async Task LoadPasswordEntriesAsync()
        {
            try
            {
                var entries = await _databaseService.GetAllPasswordEntriesAsync();
                _passwordEntries.Clear();
                FilteredEntries.Clear();
                Categories.Clear();

                foreach (var entry in entries)
                {
                    _passwordEntries.Add(entry);
                    if (!string.IsNullOrEmpty(entry.Category) && !Categories.Contains(entry.Category))
                    {
                        Categories.Add(entry.Category);
                    }
                }

                FilterEntries();
            }
            catch (Exception ex)
            {
                await _notificationService.ShowErrorAsync($"Error loading password entries: {ex.Message}");
            }
        }

        private async Task SavePasswordEntryAsync()
        {
            if (SelectedEntry == null) return;

            try
            {
                SelectedEntry.LastModified = DateTime.UtcNow;
                await _databaseService.UpdatePasswordEntryAsync(SelectedEntry);
                await LoadPasswordEntriesAsync();
                await _notificationService.ShowSuccessAsync("Password entry saved successfully!");
            }
            catch (Exception ex)
            {
                await _notificationService.ShowErrorAsync($"Error saving password entry: {ex.Message}");
            }
        }

        private async Task DeletePasswordEntryAsync()
        {
            if (SelectedEntry == null) return;

            try
            {
                var confirm = await _notificationService.ShowConfirmationAsync(
                    "Are you sure you want to delete this password entry?",
                    "Confirm Delete");

                if (!confirm) return;

                await _databaseService.DeletePasswordEntryAsync(SelectedEntry.Id);
                await LoadPasswordEntriesAsync();
                SelectedEntry = null;
                await _notificationService.ShowSuccessAsync("Password entry deleted successfully!");
            }
            catch (Exception ex)
            {
                await _notificationService.ShowErrorAsync($"Error deleting password entry: {ex.Message}");
            }
        }

        private bool CanSavePassword() => SelectedEntry != null && IsEditing;
        private bool CanDeletePassword() => SelectedEntry != null;
    }
}
