using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using SecureVault.Core.Models;
using SecureVault.Core.Services;

namespace SecureVault.UI.ViewModels
{
    public class SecureNotesViewModel : ViewModelBase
    {
        private readonly ISecureNoteService _noteService;
        private readonly IDialogService _dialogService;
        private readonly IEncryptionService _encryptionService;

        private ObservableCollection<SecureNote> _notes;
        private SecureNote _selectedNote;
        private string _searchQuery;
        private bool _isLoading;
        private bool _hasUnsavedChanges;

        public ObservableCollection<SecureNote> Notes
        {
            get => _notes;
            set => SetProperty(ref _notes, value);
        }

        public SecureNote SelectedNote
        {
            get => _selectedNote;
            set
            {
                if (_hasUnsavedChanges && _selectedNote != null)
                {
                    SaveNoteAsync(_selectedNote);
                }
                if (SetProperty(ref _selectedNote, value))
                {
                    _hasUnsavedChanges = false;
                }
            }
        }

        public string SearchQuery
        {
            get => _searchQuery;
            set
            {
                if (SetProperty(ref _searchQuery, value))
                {
                    FilterNotesAsync();
                }
            }
        }

        public bool IsLoading
        {
            get => _isLoading;
            set => SetProperty(ref _isLoading, value);
        }

        public ObservableCollection<string> Categories { get; }

        public ICommand AddNoteCommand { get; }
        public ICommand SaveNoteCommand { get; }
        public ICommand DeleteNoteCommand { get; }
        public ICommand AddTagCommand { get; }

        public SecureNotesViewModel(
            ISecureNoteService noteService,
            IDialogService dialogService,
            IEncryptionService encryptionService)
        {
            _noteService = noteService;
            _dialogService = dialogService;
            _encryptionService = encryptionService;

            Notes = new ObservableCollection<SecureNote>();
            Categories = new ObservableCollection<string>();

            AddNoteCommand = new RelayCommand(AddNewNote);
            SaveNoteCommand = new RelayCommand(async () => await SaveNoteAsync(SelectedNote));
            DeleteNoteCommand = new RelayCommand(DeleteNoteAsync);
            AddTagCommand = new RelayCommand(AddTag);

            LoadNotesAsync();
        }

        private async Task LoadNotesAsync()
        {
            try
            {
                IsLoading = true;
                var notes = await _noteService.GetAllNotesAsync();
                
                Notes.Clear();
                foreach (var note in notes)
                {
                    Notes.Add(note);
                }

                // Load categories
                var categories = notes.Select(n => n.Category)
                                    .Where(c => !string.IsNullOrEmpty(c))
                                    .Distinct()
                                    .OrderBy(c => c);
                
                Categories.Clear();
                foreach (var category in categories)
                {
                    Categories.Add(category);
                }
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error loading notes", ex.Message);
            }
            finally
            {
                IsLoading = false;
            }
        }

        private void AddNewNote()
        {
            var newNote = new SecureNote
            {
                Title = "New Note",
                Content = string.Empty,
                CreatedAt = DateTime.Now,
                LastModified = DateTime.Now
            };

            Notes.Insert(0, newNote);
            SelectedNote = newNote;
            _hasUnsavedChanges = true;
        }

        private async Task SaveNoteAsync(SecureNote note)
        {
            if (note == null) return;

            try
            {
                note.LastModified = DateTime.Now;
                
                if (string.IsNullOrWhiteSpace(note.Id))
                {
                    // New note
                    note.Id = Guid.NewGuid().ToString();
                    await _noteService.AddNoteAsync(note);
                }
                else
                {
                    // Existing note
                    await _noteService.UpdateNoteAsync(note);
                }

                _hasUnsavedChanges = false;
                await _dialogService.ShowNotificationAsync("Note saved successfully");
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error saving note", ex.Message);
            }
        }

        private async void DeleteNoteAsync()
        {
            if (SelectedNote == null) return;

            if (await _dialogService.ShowConfirmationAsync(
                "Delete Note",
                $"Are you sure you want to delete '{SelectedNote.Title}'?"))
            {
                try
                {
                    await _noteService.DeleteNoteAsync(SelectedNote.Id);
                    Notes.Remove(SelectedNote);
                    SelectedNote = Notes.FirstOrDefault();
                }
                catch (Exception ex)
                {
                    await _dialogService.ShowErrorAsync("Error deleting note", ex.Message);
                }
            }
        }

        private async void AddTag()
        {
            if (SelectedNote == null) return;

            var tag = await _dialogService.ShowInputDialogAsync("Add Tag", "Enter a new tag:");
            if (!string.IsNullOrWhiteSpace(tag))
            {
                if (SelectedNote.Tags == null)
                {
                    SelectedNote.Tags = new ObservableCollection<string>();
                }

                if (!SelectedNote.Tags.Contains(tag))
                {
                    SelectedNote.Tags.Add(tag);
                    _hasUnsavedChanges = true;
                }
            }
        }

        private async void FilterNotesAsync()
        {
            try
            {
                IsLoading = true;
                var allNotes = await _noteService.GetAllNotesAsync();

                var filtered = allNotes.AsEnumerable();

                if (!string.IsNullOrWhiteSpace(SearchQuery))
                {
                    filtered = filtered.Where(n =>
                        n.Title.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
                        n.Content.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
                        (n.Tags != null && n.Tags.Any(t => t.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase))));
                }

                Notes.Clear();
                foreach (var note in filtered)
                {
                    Notes.Add(note);
                }
            }
            catch (Exception ex)
            {
                await _dialogService.ShowErrorAsync("Error filtering notes", ex.Message);
            }
            finally
            {
                IsLoading = false;
            }
        }
    }
}
