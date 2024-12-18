using System.Windows;
using SecureVault.Core.Models;
using SecureVault.Core.Services;

namespace SecureVault.App.Views
{
    public partial class SecureNoteDialog : Window
    {
        private readonly SecureNote _note;
        private readonly EncryptionService _encryptionService;

        public SecureNote Note => _note;

        public SecureNoteDialog(SecureNote note = null, EncryptionService encryptionService = null)
        {
            InitializeComponent();

            if (encryptionService == null)
                throw new ArgumentNullException(nameof(encryptionService), "Encryption service is required");

            _encryptionService = encryptionService;
            _note = note ?? new SecureNote
            {
                CreatedAt = DateTime.UtcNow,
                LastModified = DateTime.UtcNow
            };

            DataContext = _note;

            // If editing existing note, decrypt the content
            if (note != null && !string.IsNullOrEmpty(note.EncryptedContent))
            {
                try
                {
                    string decryptedContent = _encryptionService.DecryptString(note.EncryptedContent);
                    ContentTextBox.Text = decryptedContent;
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error decrypting note: {ex.Message}", "Decryption Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    Close();
                    return;
                }
            }

            LoadCategories();
        }

        private void LoadCategories()
        {
            CategoryComboBox.Items.Clear();
            CategoryComboBox.Items.Add("Personal");
            CategoryComboBox.Items.Add("Work");
            CategoryComboBox.Items.Add("Finance");
            CategoryComboBox.Items.Add("Other");

            if (!string.IsNullOrEmpty(_note.Category))
            {
                CategoryComboBox.Text = _note.Category;
            }
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TitleTextBox.Text))
            {
                MessageBox.Show("Please enter a title for the note.", "Required Field",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                _note.Title = TitleTextBox.Text;
                _note.Category = CategoryComboBox.Text;
                _note.EncryptedContent = _encryptionService.EncryptString(ContentTextBox.Text);
                _note.LastModified = DateTime.UtcNow;

                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving note: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
