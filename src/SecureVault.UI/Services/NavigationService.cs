using System;
using Microsoft.Extensions.DependencyInjection;
using SecureVault.UI.ViewModels;

namespace SecureVault.UI.Services
{
    public interface INavigationService
    {
        event Action<ViewModelBase> CurrentViewModelChanged;
        void NavigateTo<TViewModel>() where TViewModel : ViewModelBase;
    }

    public class NavigationService : INavigationService
    {
        private readonly IServiceProvider _serviceProvider;
        public event Action<ViewModelBase> CurrentViewModelChanged;

        public NavigationService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public void NavigateTo<TViewModel>() where TViewModel : ViewModelBase
        {
            var viewModel = _serviceProvider.GetRequiredService<TViewModel>();
            CurrentViewModelChanged?.Invoke(viewModel);
        }
    }
}
