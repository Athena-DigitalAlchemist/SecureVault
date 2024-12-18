using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using SecureVault.Core.Interfaces;

namespace SecureVault.UI.ViewModels
{
    public partial class LoginViewModel : ObservableObject
    {
        private readonly IApplicationService _applicationService;
        private readonly INavigationService _navigationService;
        private readonly ILogger<LoginViewModel> _logger;

        [ObservableProperty]
        private string _masterPassword = string.Empty;

        [ObservableProperty]
        private string _errorMessage = string.Empty;

        [ObservableProperty]
        private bool _isLoading;

        [ObservableProperty]
        private bool _isNewVault;

        public bool HasError => !string.IsNullOrEmpty(ErrorMessage);

        public LoginViewModel(
            IApplicationService applicationService,
            INavigationService navigationService,
            ILogger<LoginViewModel> logger)
        {
            _applicationService = applicationService;
            _navigationService = navigationService;
            _logger = logger;
        }

        [RelayCommand]
        private async Task LoginAsync()
        {
            try
            {
                IsLoading = true;
                ErrorMessage = string.Empty;

                if (string.IsNullOrWhiteSpace(MasterPassword))
                {
                    ErrorMessage = "Please enter your master password";
                    return;
                }

                bool isValid;
                if (IsNewVault)
                {
                    await _applicationService.SetupNewVaultAsync(MasterPassword);
                    isValid = true;
                }
                else
                {
                    isValid = await _applicationService.ValidateMasterPasswordAsync(MasterPassword);
                }

                if (isValid)
                {
                    _navigationService.NavigateTo("Dashboard");
                }
                else
                {
                    ErrorMessage = "Invalid master password";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                ErrorMessage = "An error occurred during login. Please try again.";
            }
            finally
            {
                IsLoading = false;
                MasterPassword = string.Empty;
            }
        }

        [RelayCommand]
        private void ToggleNewVault()
        {
            IsNewVault = !IsNewVault;
            ErrorMessage = string.Empty;
        }
    }
}
