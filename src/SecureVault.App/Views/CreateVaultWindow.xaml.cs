using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using SecureVault.Core.Authentication;

namespace SecureVault.App.Views
{
    public partial class CreateVaultWindow : Window
    {
        private readonly MasterPasswordService _masterPasswordService;
        private readonly EncryptionService _encryptionService;
        private bool _passwordsMatch = false;

        public string MasterPassword { get; private set; }

        public CreateVaultWindow(MasterPasswordService masterPasswordService, EncryptionService encryptionService)
        {
            InitializeComponent();

            _masterPasswordService = masterPasswordService ?? throw new ArgumentNullException(nameof(masterPasswordService));
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));

            // Set initial colors for requirements
            SetRequirementColors();

            // Set focus to password box
            Loaded += (s, e) => MasterPasswordBox.Focus();
        }

        private void MasterPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            ValidatePasswords();
        }

        private void ConfirmPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            ValidatePasswords();
        }

        private void ValidatePasswords()
        {
            string password = MasterPasswordBox.Password;
            string confirmPassword = ConfirmPasswordBox.Password;

            // Check password requirements
            bool hasLength = password.Length >= 12;
            bool hasUpper = password.Any(char.IsUpper);
            bool hasLower = password.Any(char.IsLower);
            bool hasNumber = password.Any(char.IsDigit);
            bool hasSpecial = password.Any(c => !char.IsLetterOrDigit(c));

            // Update requirement indicators
            LengthRequirement.Foreground = hasLength ? Brushes.Green : Brushes.Gray;
            UppercaseRequirement.Foreground = hasUpper ? Brushes.Green : Brushes.Gray;
            LowercaseRequirement.Foreground = hasLower ? Brushes.Green : Brushes.Gray;
            NumberRequirement.Foreground = hasNumber ? Brushes.Green : Brushes.Gray;
            SpecialRequirement.Foreground = hasSpecial ? Brushes.Green : Brushes.Gray;

            // Calculate strength
            int strength = 0;
            if (hasLength) strength++;
            if (hasUpper) strength++;
            if (hasLower) strength++;
            if (hasNumber) strength++;
            if (hasSpecial) strength++;

            // Update strength indicator
            StrengthIndicator.Value = strength * 20;
            switch (strength)
            {
                case 0:
                case 1:
                    StrengthIndicator.Foreground = Brushes.Red;
                    StrengthText.Text = "Password Strength: Very Weak";
                    break;
                case 2:
                    StrengthIndicator.Foreground = Brushes.OrangeRed;
                    StrengthText.Text = "Password Strength: Weak";
                    break;
                case 3:
                    StrengthIndicator.Foreground = Brushes.Orange;
                    StrengthText.Text = "Password Strength: Medium";
                    break;
                case 4:
                    StrengthIndicator.Foreground = Brushes.YellowGreen;
                    StrengthText.Text = "Password Strength: Strong";
                    break;
                case 5:
                    StrengthIndicator.Foreground = Brushes.Green;
                    StrengthText.Text = "Password Strength: Very Strong";
                    break;
            }

            // Check if passwords match
            _passwordsMatch = !string.IsNullOrEmpty(password) &&
                            !string.IsNullOrEmpty(confirmPassword) &&
                            password == confirmPassword;

            if (string.IsNullOrEmpty(confirmPassword))
            {
                ErrorMessageText.Text = string.Empty;
            }
            else if (!_passwordsMatch)
            {
                ErrorMessageText.Text = "Passwords do not match";
            }
            else
            {
                ErrorMessageText.Text = string.Empty;
            }

            // Enable/disable create button
            CreateVaultButton.IsEnabled = strength == 5 && _passwordsMatch;
        }

        private void CreateVaultButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string password = MasterPasswordBox.Password;

                // Validate password one final time
                var (isValid, message) = _masterPasswordService.ValidatePasswordStrength(password);
                if (!isValid)
                {
                    ErrorMessageText.Text = message;
                    return;
                }

                // Store the password and close
                MasterPassword = password;
                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                ErrorMessageText.Text = "Failed to create vault. Please try again.";
            }
        }

        private void BackToLogin_MouseDown(object sender, MouseButtonEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void SetRequirementColors()
        {
            LengthRequirement.Foreground = Brushes.Gray;
            UppercaseRequirement.Foreground = Brushes.Gray;
            LowercaseRequirement.Foreground = Brushes.Gray;
            NumberRequirement.Foreground = Brushes.Gray;
            SpecialRequirement.Foreground = Brushes.Gray;
        }
    }
}
