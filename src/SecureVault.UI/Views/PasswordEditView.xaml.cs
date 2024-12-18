using System.Windows;
using System.Windows.Controls;
using SecureVault.UI.ViewModels;

namespace SecureVault.UI.Views
{
    public partial class PasswordEditView : Window
    {
        public PasswordEditView()
        {
            InitializeComponent();
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (DataContext is PasswordEditViewModel viewModel)
            {
                viewModel.OnPasswordChanged(sender, e);
            }
        }
    }
}
