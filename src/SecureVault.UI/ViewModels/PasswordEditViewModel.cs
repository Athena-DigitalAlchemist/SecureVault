using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Input;
using SecureVault.Core.Models;
using SecureVault.Core.Services;

namespace SecureVault.UI.ViewModels
{
    public class PasswordEditViewModel : ViewModelBase
    {
        private readonly IPasswordService _passwordService;
        private readonly IPasswordGeneratorService _passwordGenerator;
        private readonly PasswordEntry _existingPassword;

        private string _title;
        private string _url;
        private string _username;
        private string _category;
        private string _notes;
        private bool _showPassword;
        private string _windowTitle;
        private int _passwordStrength;
        private string _passwordStrengthText;
        private ObservableCollection<string> _passwordWeaknesses;
        private bool _hasWeaknesses;

        public string Title
        {
            get => _title;
            set => SetProperty(ref _title, value);
        }

        public string Url
        {
            get => _url;
            set => SetProperty(ref _url, value);
        }

        public string Username
        {
            get => _username;
            set => SetProperty(ref _username, value);
        }

        public string Category
        {
            get => _category;
            set => SetProperty(ref _category, value);
        }

        public string Notes
        {
            get => _notes;
            set => SetProperty(ref _notes, value);
        }

        public bool ShowPassword
        {
            get => _showPassword;
            set => SetProperty(ref _showPassword, value);
        }

        public string WindowTitle
        {
            get => _windowTitle;
            set => SetProperty(ref _windowTitle, value);
        }

        public int PasswordStrength
        {
            get => _passwordStrength;
            set => SetProperty(ref _passwordStrength, value);
        }

        public string PasswordStrengthText
        {
            get => _passwordStrengthText;
            set => SetProperty(ref _passwordStrengthText, value);
        }

        public ObservableCollection<string> PasswordWeaknesses
        {
            get => _passwordWeaknesses;
            set => SetProperty(ref _passwordWeaknesses, value);
        }

        public bool HasWeaknesses
        {
            get => _hasWeaknesses;
            set => SetProperty(ref _hasWeaknesses, value);
        }

        public ObservableCollection<string> Categories { get; }

        public ICommand SaveCommand { get; }
        public ICommand CancelCommand { get; }
        public ICommand GeneratePasswordCommand { get; }

        public PasswordEditViewModel(
            IPasswordService passwordService,
            IPasswordGeneratorService passwordGenerator,
            PasswordEntry existingPassword = null)
        {
            _passwordService = passwordService;
            _passwordGenerator = passwordGenerator;
            _existingPassword = existingPassword;

            Categories = new ObservableCollection<string>();
            PasswordWeaknesses = new ObservableCollection<string>();
            WindowTitle = existingPassword == null ? "Add New Password" : "Edit Password";

            SaveCommand = new RelayCommand<PasswordBox>(SavePasswordAsync);
            CancelCommand = new RelayCommand(Cancel);
            GeneratePasswordCommand = new RelayCommand(GeneratePassword);

            LoadCategories();
            LoadExistingPassword();
        }

        private async void LoadCategories()
        {
            var categories = await _passwordService.GetCategoriesAsync();
            Categories.Clear();
            foreach (var category in categories)
            {
                Categories.Add(category);
            }
        }

        private void LoadExistingPassword()
        {
            if (_existingPassword != null)
            {
                Title = _existingPassword.Title;
                Url = _existingPassword.Url;
                Username = _existingPassword.Username;
                Category = _existingPassword.Category;
                Notes = _existingPassword.Notes;
            }
        }

        private async void SavePasswordAsync(PasswordBox passwordBox)
        {
            if (string.IsNullOrWhiteSpace(Title))
            {
                await _dialogService.ShowErrorAsync("Validation Error", "Title is required.");
                return;
            }

            if (string.IsNullOrWhiteSpace(passwordBox.Password) && _existingPassword == null)
            {
                await _dialogService.ShowErrorAsync("Validation Error", "Password is required.");
                return;
            }

            try
            {
                var password = _existingPassword ?? new PasswordEntry();
                password.Title = Title;
                password.Url = Url;
                password.Username = Username;
                password.Category = Category;
                password.Notes = Notes;

                if (!string.IsNullOrEmpty(passwordBox.Password))
                {
                    // Only update password if a new one is provided
                    password.SetPassword(passwordBox.Password);
                }

                if (_existingPassword == null)
                {
                    await _passwordService.AddPasswordAsync(password);
                }
                else
                {
                    await _passwordService.UpdatePasswordAsync(password);
                }

                DialogResult = true;
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error saving password", ex.Message);
            }
        }

        private void Cancel()
        {
            DialogResult = false;
        }

        private async void UpdatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                PasswordStrength = 0;
                PasswordStrengthText = "No password";
                PasswordWeaknesses.Clear();
                HasWeaknesses = false;
                return;
            }

            var (score, weaknesses) = await _passwordService.ValidatePasswordStrengthAsync(password);
            PasswordStrength = score;
            
            PasswordStrengthText = score switch
            {
                <= 20 => "Very Weak",
                <= 40 => "Weak",
                <= 60 => "Medium",
                <= 80 => "Strong",
                _ => "Very Strong"
            };

            PasswordWeaknesses.Clear();
            foreach (var weakness in weaknesses)
            {
                PasswordWeaknesses.Add(weakness);
            }
            HasWeaknesses = PasswordWeaknesses.Count > 0;
        }

        private async void GeneratePassword()
        {
            var password = await _passwordGenerator.GeneratePasswordAsync(new PasswordGenerationOptions
            {
                Length = 16,
                IncludeUppercase = true,
                IncludeLowercase = true,
                IncludeNumbers = true,
                IncludeSpecialCharacters = true
            });

            if (password != null)
            {
                var passwordBox = GetPasswordBox();
                if (passwordBox != null)
                {
                    passwordBox.Password = password;
                    UpdatePasswordStrength(password);
                }
            }
        }

        private void OnPasswordChanged(object sender, RoutedEventArgs e)
        {
            if (sender is PasswordBox passwordBox)
            {
                UpdatePasswordStrength(passwordBox.Password);
            }
        }
    }
}
