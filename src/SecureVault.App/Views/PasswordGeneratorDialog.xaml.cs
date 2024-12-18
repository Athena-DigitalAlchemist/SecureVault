using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SecureVault.Core.Services;

namespace SecureVault.App.Views
{
    public partial class PasswordGeneratorDialog : Window
    {
        private readonly PasswordGeneratorService _passwordGenerator;
        public string GeneratedPassword { get; private set; }

        public PasswordGeneratorDialog(PasswordGeneratorService passwordGenerator)
        {
            InitializeComponent();

            _passwordGenerator = passwordGenerator ?? throw new ArgumentNullException(nameof(passwordGenerator));

            // Generate initial password
            GenerateNewPassword();
        }

        private void GenerateNewPassword()
        {
            try
            {
                // Get length from slider
                int length = (int)LengthSlider.Value;

                // Create options
                var options = new PasswordGeneratorService.PasswordOptions
                {
                    Length = length,
                    IncludeUppercase = UppercaseCheck.IsChecked ?? false,
                    IncludeLowercase = LowercaseCheck.IsChecked ?? false,
                    IncludeNumbers = NumbersCheck.IsChecked ?? false,
                    IncludeSpecial = SpecialCheck.IsChecked ?? false,
                    ExcludeSimilar = ExcludeSimilarCheck.IsChecked ?? false,
                    ExcludeAmbiguous = ExcludeAmbiguousCheck.IsChecked ?? false,
                    CustomCharacters = CustomCharsBox.Text
                };

                // Validate at least one character set is selected
                if (!options.IncludeUppercase && !options.IncludeLowercase &&
                    !options.IncludeNumbers && !options.IncludeSpecial &&
                    string.IsNullOrEmpty(options.CustomCharacters))
                {
                    MessageBox.Show(
                        "Please select at least one character set.",
                        "Validation Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning
                    );
                    return;
                }

                // Generate password
                GeneratedPassword = _passwordGenerator.GeneratePassword(options);
                GeneratedPasswordBox.Text = GeneratedPassword;

                // Update strength indicator
                UpdatePasswordStrength(GeneratedPassword);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Failed to generate password: " + ex.Message,
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
            }
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

        private void LengthSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (LengthBox != null)  // Check for null during initialization
            {
                LengthBox.Text = ((int)e.NewValue).ToString();
                GenerateNewPassword();
            }
        }

        private void LengthBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (int.TryParse(LengthBox.Text, out int length))
            {
                // Ensure length is within bounds
                length = Math.Max(4, Math.Min(128, length));
                LengthSlider.Value = length;
            }
        }

        private void CharacterSet_Changed(object sender, RoutedEventArgs e)
        {
            GenerateNewPassword();
        }

        private void Option_Changed(object sender, RoutedEventArgs e)
        {
            GenerateNewPassword();
        }

        private void CustomCharsBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            GenerateNewPassword();
        }

        private void Generate_Click(object sender, RoutedEventArgs e)
        {
            GenerateNewPassword();
        }

        private void Copy_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(GeneratedPassword))
            {
                Clipboard.SetText(GeneratedPassword);
                MessageBox.Show(
                    "Password copied to clipboard!",
                    "Success",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information
                );
            }
        }

        private void UsePassword_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(GeneratedPassword))
            {
                DialogResult = true;
                Close();
            }
        }
    }
}
