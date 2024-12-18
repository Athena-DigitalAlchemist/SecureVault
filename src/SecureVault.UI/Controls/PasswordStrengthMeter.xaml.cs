using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using SecureVault.Core.Services;

namespace SecureVault.UI.Controls
{
    public partial class PasswordStrengthMeter : INotifyPropertyChanged
    {
        private readonly IPasswordStrengthService _strengthService;
        private string _password;
        private int _score;
        private string _strengthText;
        private Brush _strengthColor;
        private ObservableCollection<PasswordRequirement> _requirements;

        public event PropertyChangedEventHandler PropertyChanged;

        public static readonly DependencyProperty PasswordProperty =
            DependencyProperty.Register(
                "Password",
                typeof(string),
                typeof(PasswordStrengthMeter),
                new PropertyMetadata(string.Empty, OnPasswordChanged));

        public string Password
        {
            get => (string)GetValue(PasswordProperty);
            set => SetValue(PasswordProperty, value);
        }

        public int Score
        {
            get => _score;
            private set
            {
                _score = value;
                OnPropertyChanged(nameof(Score));
                UpdateStrengthIndicators();
            }
        }

        public string StrengthText
        {
            get => _strengthText;
            private set
            {
                _strengthText = value;
                OnPropertyChanged(nameof(StrengthText));
            }
        }

        public Brush StrengthColor
        {
            get => _strengthColor;
            private set
            {
                _strengthColor = value;
                OnPropertyChanged(nameof(StrengthColor));
            }
        }

        public ObservableCollection<PasswordRequirement> Requirements
        {
            get => _requirements;
            private set
            {
                _requirements = value;
                OnPropertyChanged(nameof(Requirements));
            }
        }

        // Strength Level Colors
        public Brush Level1Color => Score >= 1 ? GetStrengthColor() : Brushes.LightGray;
        public Brush Level2Color => Score >= 2 ? GetStrengthColor() : Brushes.LightGray;
        public Brush Level3Color => Score >= 3 ? GetStrengthColor() : Brushes.LightGray;
        public Brush Level4Color => Score >= 4 ? GetStrengthColor() : Brushes.LightGray;

        public PasswordStrengthMeter(IPasswordStrengthService strengthService)
        {
            InitializeComponent();
            DataContext = this;
            _strengthService = strengthService;
            InitializeRequirements();
        }

        private static void OnPasswordChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var meter = (PasswordStrengthMeter)d;
            meter.EvaluatePassword((string)e.NewValue);
        }

        private void InitializeRequirements()
        {
            Requirements = new ObservableCollection<PasswordRequirement>
            {
                new PasswordRequirement { Text = "At least 8 characters", Icon = "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z" },
                new PasswordRequirement { Text = "Contains uppercase letters", Icon = "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z" },
                new PasswordRequirement { Text = "Contains lowercase letters", Icon = "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z" },
                new PasswordRequirement { Text = "Contains numbers", Icon = "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z" },
                new PasswordRequirement { Text = "Contains special characters", Icon = "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z" }
            };
        }

        private void EvaluatePassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                Score = 0;
                return;
            }

            var result = _strengthService.EvaluatePassword(password);
            Score = result.Score;

            // Update requirements
            Requirements[0].IsMet = password.Length >= 8;
            Requirements[1].IsMet = result.HasUppercase;
            Requirements[2].IsMet = result.HasLowercase;
            Requirements[3].IsMet = result.HasNumbers;
            Requirements[4].IsMet = result.HasSpecialChars;

            OnPropertyChanged(nameof(Level1Color));
            OnPropertyChanged(nameof(Level2Color));
            OnPropertyChanged(nameof(Level3Color));
            OnPropertyChanged(nameof(Level4Color));
        }

        private void UpdateStrengthIndicators()
        {
            switch (Score)
            {
                case 0:
                    StrengthText = "Very Weak";
                    StrengthColor = new SolidColorBrush(Colors.Red);
                    break;
                case 1:
                    StrengthText = "Weak";
                    StrengthColor = new SolidColorBrush(Colors.OrangeRed);
                    break;
                case 2:
                    StrengthText = "Fair";
                    StrengthColor = new SolidColorBrush(Colors.Orange);
                    break;
                case 3:
                    StrengthText = "Strong";
                    StrengthColor = new SolidColorBrush(Colors.LightGreen);
                    break;
                case 4:
                    StrengthText = "Very Strong";
                    StrengthColor = new SolidColorBrush(Colors.Green);
                    break;
            }
        }

        private Brush GetStrengthColor()
        {
            return Score switch
            {
                1 => new SolidColorBrush(Colors.OrangeRed),
                2 => new SolidColorBrush(Colors.Orange),
                3 => new SolidColorBrush(Colors.LightGreen),
                4 => new SolidColorBrush(Colors.Green),
                _ => new SolidColorBrush(Colors.Red)
            };
        }

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class PasswordRequirement : INotifyPropertyChanged
    {
        private bool _isMet;
        public string Text { get; set; }
        public string Icon { get; set; }

        public bool IsMet
        {
            get => _isMet;
            set
            {
                _isMet = value;
                OnPropertyChanged(nameof(IsMet));
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
