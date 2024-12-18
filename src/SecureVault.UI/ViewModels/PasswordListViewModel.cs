using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureVault.Core.Models;
using SecureVault.Core.Services;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace SecureVault.UI.ViewModels
{
    public partial class PasswordListViewModel : ObservableObject
    {
        private readonly IPasswordService _passwordService;
        private readonly IClipboardService _clipboardService;
        private readonly IDialogService _dialogService;

        [ObservableProperty]
        private bool _isLoading;

        [ObservableProperty]
        private string _searchQuery = string.Empty;

        [ObservableProperty]
        private ObservableCollection<PasswordEntry> _passwords;

        [ObservableProperty]
        private ObservableCollection<string> _categories;

        [ObservableProperty]
        private string _selectedCategory;

        [ObservableProperty]
        private string _selectedSortOption;

        [ObservableProperty]
        private ObservableCollection<PasswordEntry> _filteredPasswords;

        [ObservableProperty]
        private bool _isSearching;

        [ObservableProperty]
        private string _searchResultText;

        public ObservableCollection<string> SortOptions { get; } = new()
        {
            "Title (A-Z)",
            "Title (Z-A)",
            "Last Modified",
            "Category"
        };

        public int PasswordCount => Passwords?.Count ?? 0;

        private System.Timers.Timer _searchDebounceTimer;
        private const int SearchDebounceDelay = 300; // milliseconds

        public PasswordListViewModel(
            IPasswordService passwordService,
            IClipboardService clipboardService,
            IDialogService dialogService)
        {
            _passwordService = passwordService;
            _clipboardService = clipboardService;
            _dialogService = dialogService;

            Passwords = new ObservableCollection<PasswordEntry>();
            FilteredPasswords = new ObservableCollection<PasswordEntry>();
            Categories = new ObservableCollection<string>();

            // Initialize search debounce timer
            _searchDebounceTimer = new System.Timers.Timer(SearchDebounceDelay);
            _searchDebounceTimer.Elapsed += async (s, e) =>
            {
                await Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    UpdateFilteredPasswords();
                });
            };
            _searchDebounceTimer.AutoReset = false;

            LoadDataAsync().ConfigureAwait(false);
        }

        private async Task LoadDataAsync()
        {
            try
            {
                IsLoading = true;
                var passwords = await _passwordService.GetAllPasswordsAsync();
                
                Passwords.Clear();
                FilteredPasswords.Clear();
                foreach (var password in passwords)
                {
                    Passwords.Add(password);
                    FilteredPasswords.Add(password);
                }

                // Load categories
                var categories = passwords.Select(p => p.Category)
                                       .Distinct()
                                       .OrderBy(c => c);
                
                Categories.Clear();
                Categories.Add("All"); // Default category
                foreach (var category in categories)
                {
                    if (!string.IsNullOrEmpty(category))
                    {
                        Categories.Add(category);
                    }
                }

                SelectedCategory = "All";
                SelectedSortOption = SortOptions[0];
                SearchResultText = $"Showing all {passwords.Count} passwords";
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error Loading Passwords", 
                    "Failed to load passwords. Please try again.");
            }
            finally
            {
                IsLoading = false;
            }
        }

        [RelayCommand]
        private async Task AddPassword()
        {
            try
            {
                var result = await _dialogService.ShowAddPasswordDialogAsync();
                if (result != null)
                {
                    await _passwordService.AddPasswordAsync(result);
                    await LoadDataAsync();
                }
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error", 
                    "Failed to add password. Please try again.");
            }
        }

        [RelayCommand]
        private async Task EditPassword(PasswordEntry password)
        {
            try
            {
                var result = await _dialogService.ShowEditPasswordDialogAsync(password);
                if (result != null)
                {
                    await _passwordService.UpdatePasswordAsync(result);
                    await LoadDataAsync();
                }
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error", 
                    "Failed to update password. Please try again.");
            }
        }

        [RelayCommand]
        private async Task DeletePassword(PasswordEntry password)
        {
            try
            {
                var result = await _dialogService.ShowConfirmationAsync(
                    "Delete Password",
                    $"Are you sure you want to delete the password for {password.Title}?");

                if (result)
                {
                    await _passwordService.DeletePasswordAsync(password.Id);
                    await LoadDataAsync();
                }
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error", 
                    "Failed to delete password. Please try again.");
            }
        }

        [RelayCommand]
        private async Task CopyPassword(PasswordEntry password)
        {
            try
            {
                var decryptedPassword = await _passwordService.GetDecryptedPasswordAsync(password.Id);
                await _clipboardService.CopyToClipboardAsync(decryptedPassword);
                
                // Show a temporary notification
                await _dialogService.ShowNotificationAsync("Password Copied", 
                    "Password has been copied to clipboard");
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error", 
                    "Failed to copy password. Please try again.");
            }
        }

        partial void OnSearchQueryChanged(string value)
        {
            _searchDebounceTimer.Stop();
            _searchDebounceTimer.Start();
        }

        partial void OnSelectedCategoryChanged(string value)
        {
            UpdateFilteredPasswords();
        }

        partial void OnSelectedSortOptionChanged(string value)
        {
            UpdateFilteredPasswords();
        }

        private void UpdateFilteredPasswords()
        {
            IsSearching = true;

            try
            {
                var query = SearchQuery?.ToLower() ?? "";
                var category = SelectedCategory;

                var filtered = Passwords.Where(p =>
                    (string.IsNullOrEmpty(query) ||
                     p.Title.ToLower().Contains(query) ||
                     p.Username.ToLower().Contains(query) ||
                     p.Website?.ToLower().Contains(query) == true ||
                     p.Notes?.ToLower().Contains(query) == true) &&
                    (category == "All" || p.Category == category)
                ).ToList();

                // Apply sorting
                filtered = SelectedSortOption switch
                {
                    "Title (A-Z)" => filtered.OrderBy(p => p.Title).ToList(),
                    "Title (Z-A)" => filtered.OrderByDescending(p => p.Title).ToList(),
                    "Last Modified" => filtered.OrderByDescending(p => p.LastModified).ToList(),
                    "Category" => filtered.OrderBy(p => p.Category).ThenBy(p => p.Title).ToList(),
                    _ => filtered
                };

                FilteredPasswords.Clear();
                foreach (var password in filtered)
                {
                    FilteredPasswords.Add(password);
                }

                // Update search result text
                if (string.IsNullOrEmpty(query) && category == "All")
                {
                    SearchResultText = $"Showing all {filtered.Count} passwords";
                }
                else
                {
                    var categoryText = category == "All" ? "" : $" in {category}";
                    var searchText = string.IsNullOrEmpty(query) ? "" : $" matching '{query}'";
                    SearchResultText = $"Found {filtered.Count} passwords{categoryText}{searchText}";
                }
            }
            finally
            {
                IsSearching = false;
            }
        }
    }
}
