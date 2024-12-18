using System.Linq;
using System.Windows;
using System.Windows.Controls;
using SecureVault.UI.ViewModels;

namespace SecureVault.UI.Views
{
    public partial class SecureFilesView : UserControl
    {
        private SecureFilesViewModel ViewModel => DataContext as SecureFilesViewModel;

        public SecureFilesView()
        {
            InitializeComponent();
        }

        private void Grid_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
                DropOverlay.Visibility = Visibility.Visible;
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
            e.Handled = true;
        }

        private void Grid_DragLeave(object sender, DragEventArgs e)
        {
            DropOverlay.Visibility = Visibility.Collapsed;
            e.Handled = true;
        }

        private async void Grid_Drop(object sender, DragEventArgs e)
        {
            DropOverlay.Visibility = Visibility.Collapsed;

            if (e.Data.GetDataPresent(DataFormats.FileDrop) && ViewModel != null)
            {
                var files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files != null && files.Any())
                {
                    await ViewModel.UploadFilesAsync(files);
                }
            }
            e.Handled = true;
        }
    }
}
