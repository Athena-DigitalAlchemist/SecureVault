using System;
using System.Windows.Input;
using SecureVault.Core.Models;
using SecureVault.Core.Services;
using SecureVault.Core.Interfaces;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SecureVault.UI.ViewModels
{
    public partial class MainWindowViewModel : ObservableObject
    {
        private readonly IApplicationService _applicationService;
        private readonly INavigationService _navigationService;

        [ObservableProperty]
        private ViewModelBase _currentView;

        [ObservableProperty]
        private User _currentUser;

        public MainWindowViewModel(
            IApplicationService applicationService,
            INavigationService navigationService)
        {
            _applicationService = applicationService;
            _navigationService = navigationService;

            // Subscribe to navigation events
            _navigationService.CurrentViewModelChanged += OnCurrentViewModelChanged;

            // Initialize the application
            InitializeApplicationAsync();
        }

        private async void InitializeApplicationAsync()
        {
            await _applicationService.InitializeAsync();
            _navigationService.NavigateTo("Login");
        }

        [RelayCommand]
        private void Navigate(string destination)
        {
            _navigationService.NavigateTo(destination);
        }

        [RelayCommand]
        private async Task LogoutAsync()
        {
            CurrentUser = null;
            _navigationService.NavigateTo("Login");
        }

        private void OnCurrentViewModelChanged(ViewModelBase viewModel)
        {
            CurrentView = viewModel;
        }
    }
}
