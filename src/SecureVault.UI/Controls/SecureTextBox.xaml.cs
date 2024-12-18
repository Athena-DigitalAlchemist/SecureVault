using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MaterialDesignThemes.Wpf;

namespace SecureVault.UI.Controls
{
    public partial class SecureTextBox : UserControl
    {
        private bool _isPasswordVisible;
        private readonly TextBox _textBox;

        public static readonly DependencyProperty PlaceholderTextProperty =
            DependencyProperty.Register(nameof(PlaceholderText), typeof(string), typeof(SecureTextBox), new PropertyMetadata(string.Empty));

        public static readonly DependencyProperty SecureTextProperty =
            DependencyProperty.Register(nameof(SecureText), typeof(string), typeof(SecureTextBox), 
                new FrameworkPropertyMetadata(string.Empty, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault));

        public string PlaceholderText
        {
            get => (string)GetValue(PlaceholderTextProperty);
            set => SetValue(PlaceholderTextProperty, value);
        }

        public string SecureText
        {
            get => (string)GetValue(SecureTextProperty);
            set => SetValue(SecureTextProperty, value);
        }

        public SecureTextBox()
        {
            InitializeComponent();
            _textBox = new TextBox
            {
                Style = (Style)FindResource("SecureTextBoxStyle"),
                Visibility = Visibility.Collapsed
            };
            Grid.SetColumn(_textBox, 0);
            ((Grid)Content).Children.Add(_textBox);

            PART_PasswordBox.PasswordChanged += OnPasswordChanged;
            PART_ToggleVisibilityButton.Click += OnToggleVisibility;
        }

        private void OnPasswordChanged(object sender, RoutedEventArgs e)
        {
            SecureText = PART_PasswordBox.Password;
        }

        private void OnToggleVisibility(object sender, RoutedEventArgs e)
        {
            _isPasswordVisible = !_isPasswordVisible;

            if (_isPasswordVisible)
            {
                _textBox.Text = PART_PasswordBox.Password;
                PART_PasswordBox.Visibility = Visibility.Collapsed;
                _textBox.Visibility = Visibility.Visible;
                ((PackIcon)VisibilityIcon).Kind = PackIconKind.EyeOffOutline;
            }
            else
            {
                PART_PasswordBox.Password = _textBox.Text;
                _textBox.Visibility = Visibility.Collapsed;
                PART_PasswordBox.Visibility = Visibility.Visible;
                ((PackIcon)VisibilityIcon).Kind = PackIconKind.EyeOutline;
            }
        }
    }
}
