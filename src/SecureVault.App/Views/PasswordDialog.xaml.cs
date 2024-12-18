using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SecureVault.Core.Models;
using SecureVault.Core.Services;

namespace SecureVault.App.Views
{
    public partial class PasswordDialog : Window
    {
        private readonly PasswordGeneratorService _passwordGenerator;
        private bool _isEditMode;
        private bool _isPasswordVisible;
        private TextBox _passwordTextBox;

        public PasswordEntry PasswordEntry { get; private set; }

        public PasswordDialog(PasswordGeneratorService passwordGenerator, PasswordEntry existingEntry = null)
        {
            InitializeComponent();

            _passwordGenerator = passwordGenerator ?? throw new ArgumentNullException(nameof(passwordGenerator));
            _isEditMode = existingEntry != null;

            // Set up the dialog based on mode
            HeaderText.Text = _isEditMode ? "Edit Password" : "Add New Password";
            SaveButton.Content = _isEditMode ? "Update" : "Save";

            // Create password text box for toggling visibility
            _passwordTextBox = new TextBox
            {
                Height = PasswordBox.Height,
                Visibility = Visibility.Collapsed
            };
            var parent = (Grid)PasswordBox.Parent;
            parent.Children.Add(_passwordTextBox);
            Grid.SetColumn(_passwordTextBox, 0);

            // Load existing entry if in edit mode
            if (_isEditMode)
            {
                LoadExistingEntry(existingEntry);
            }
            else
            {
                CategoryBox.SelectedIndex = 0;
                HistoryCount.SelectedIndex = 0;
            }

            // Set focus to title box
            Loaded += (s, e) => TitleBox.Focus();
        }

        private void LoadExistingEntry(PasswordEntry entry)
        {
            TitleBox.Text = entry.Title;
            UsernameBox.Text = entry.Username;
            PasswordBox.Password = entry.Password;
            _passwordTextBox.Text = entry.Password;
            UrlBox.Text = entry.Url;
            NotesBox.Text = entry.Notes;

            // Set category
            for (int i = 0; i < CategoryBox.Items.Count; i++)
            {
                if (((ComboBoxItem)CategoryBox.Items[i]).Content.ToString() == entry.Category)
                {
                    CategoryBox.SelectedIndex = i;
                    break;
                }
            }

            // Set additional settings
            AutoTypeEnabled.IsChecked = entry.AutoTypeEnabled;
            AutoTypeSequence.Text = entry.AutoTypeSequence;
            KeepHistory.IsChecked = entry.KeepHistory;

            if (entry.HistoryCount > 0)
            {
                for (int i = 0; i < HistoryCount.Items.Count; i++)
                {
                    if (((ComboBoxItem)HistoryCount.Items[i]).Content.ToString() == entry.HistoryCount.ToString())
                    {
                        HistoryCount.SelectedIndex = i;
                        break;
                    }
                }
            }

            UpdatePasswordStrength(entry.Password);
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (!_isPasswordVisible)
            {
                _passwordTextBox.Text = PasswordBox.Password;
            }
            UpdatePasswordStrength(PasswordBox.Password);
        }

        private void UpdatePasswordStrength(string password)
        {
            double strength = _passwordGenerator.CalculatePasswordStrength(password);
            StrengthIndicator.Value = strength;

            // Update color and text based on strength
            if (strength < 20)
            {
                StrengthIndicator.Foreground = Brushes.Red;
                StrengthText.Text = "Password Strength: Very Weak";
            }
            else if (strength < 40)
            {
                StrengthIndicator.Foreground = Brushes.OrangeRed;
                StrengthText.Text = "Password Strength: Weak";
            }
            else if (strength < 60)
            {
                StrengthIndicator.Foreground = Brushes.Orange;
                StrengthText.Text = "Password Strength: Medium";
            }
            else if (strength < 80)
            {
                StrengthIndicator.Foreground = Brushes.YellowGreen;
                StrengthText.Text = "Password Strength: Strong";
            }
            else
            {
                StrengthIndicator.Foreground = Brushes.Green;
                StrengthText.Text = "Password Strength: Very Strong";
            }
        }

        private void TogglePassword_Click(object sender, RoutedEventArgs e)
        {
            _isPasswordVisible = !_isPasswordVisible;

            if (_isPasswordVisible)
            {
                PasswordBox.Visibility = Visibility.Collapsed;
                _passwordTextBox.Visibility = Visibility.Visible;
                _passwordTextBox.Text = PasswordBox.Password;
                ((Button)sender).Content = "Hide";
            }
            else
            {
                PasswordBox.Visibility = Visibility.Visible;
                _passwordTextBox.Visibility = Visibility.Collapsed;
                PasswordBox.Password = _passwordTextBox.Text;
                ((Button)sender).Content = "Show";
            }
        }

        private void GeneratePassword_Click(object sender, RoutedEventArgs e)
        {
            var options = new PasswordGeneratorService.PasswordOptions
            {
                Length = 16,
                IncludeLowercase = true,
                IncludeUppercase = true,
                IncludeNumbers = true,
                IncludeSpecial = true
            };

            string newPassword = _passwordGenerator.GeneratePassword(options);
            PasswordBox.Password = newPassword;
            _passwordTextBox.Text = newPassword;
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            // Validate input
            if (string.IsNullOrWhiteSpace(TitleBox.Text))
            {
                MessageBox.Show("Title is required.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                TitleBox.Focus();
                return;
            }

            if (string.IsNullOrWhiteSpace(PasswordBox.Password))
            {
                MessageBox.Show("Password is required.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                PasswordBox.Focus();
                return;
            }

            // Create password entry
            PasswordEntry = new PasswordEntry
            {
                Title = TitleBox.Text.Trim(),
                Username = UsernameBox.Text?.Trim(),
                Password = PasswordBox.Password,
                Url = UrlBox.Text?.Trim(),
                Category = ((ComboBoxItem)CategoryBox.SelectedItem).Content.ToString(),
                Notes = NotesBox.Text?.Trim(),
                AutoTypeEnabled = AutoTypeEnabled.IsChecked ?? false,
                AutoTypeSequence = AutoTypeSequence.Text,
                KeepHistory = KeepHistory.IsChecked ?? false,
                HistoryCount = KeepHistory.IsChecked ?? false
                    ? int.Parse(((ComboBoxItem)HistoryCount.SelectedItem).Content.ToString())
                    : 0,
                LastModified = DateTime.UtcNow
            };

            DialogResult = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
