using System.Windows;
using System.Windows.Input;
using SecureVault.Core.Authentication;

namespace SecureVault.App.Views
{
    public partial class LoginWindow : Window
    {
        private readonly MasterPasswordService _masterPasswordService;
        private readonly EncryptionService _encryptionService;

        public string MasterPassword { get; private set; }

        public LoginWindow(MasterPasswordService masterPasswordService, EncryptionService encryptionService)
        {
            InitializeComponent();

            _masterPasswordService = masterPasswordService ?? throw new ArgumentNullException(nameof(masterPasswordService));
            _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));

            // Set focus to password box
            Loaded += (s, e) => MasterPasswordBox.Focus();
        }

        private void MasterPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            string password = MasterPasswordBox.Password;

            // Validate password strength
            var (isValid, message) = _masterPasswordService.ValidatePasswordStrength(password);

            if (string.IsNullOrEmpty(password))
            {
                PasswordStrengthText.Text = string.Empty;
                UnlockButton.IsEnabled = false;
            }
            else if (!isValid)
            {
                PasswordStrengthText.Text = message;
                UnlockButton.IsEnabled = false;
            }
            else
            {
                PasswordStrengthText.Text = "Password strength: Strong";
                UnlockButton.IsEnabled = true;
            }

            ErrorMessageText.Text = string.Empty;
        }

        private void UnlockButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string password = MasterPasswordBox.Password;

                // TODO: Verify master password against stored hash
                // For now, just store the password and close the window
                MasterPassword = password;
                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                ErrorMessageText.Text = "Failed to unlock vault. Please check your password and try again.";
                MasterPasswordBox.Password = string.Empty;
                MasterPasswordBox.Focus();
            }
        }

        private void CreateNewVaultLink_MouseDown(object sender, MouseButtonEventArgs e)
        {
            var createVaultWindow = new CreateVaultWindow(_masterPasswordService, _encryptionService);
            if (createVaultWindow.ShowDialog() == true)
            {
                // User created a new vault, use the master password
                MasterPassword = createVaultWindow.MasterPassword;
                DialogResult = true;
                Close();
            }
        }
    }
}
