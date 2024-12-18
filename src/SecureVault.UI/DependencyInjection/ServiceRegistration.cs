using Microsoft.Extensions.DependencyInjection;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Services;
using SecureVault.UI.ViewModels;

namespace SecureVault.UI.DependencyInjection
{
    public static class ServiceRegistration
    {
        public static IServiceCollection AddSecureVaultServices(this IServiceCollection services)
        {
            // Register Core Services
            services.AddSingleton<IApplicationService, ApplicationService>();
            services.AddSingleton<IEncryptionService, EncryptionService>();
            services.AddSingleton<IDatabaseService, DatabaseService>();
            services.AddSingleton<IKeyManagementService, KeyManagementService>();
            services.AddSingleton<INavigationService, NavigationService>();

            // Register ViewModels
            services.AddTransient<MainWindowViewModel>();
            services.AddTransient<LoginViewModel>();
            services.AddTransient<DashboardViewModel>();
            services.AddTransient<PasswordListViewModel>();
            services.AddTransient<PasswordEditViewModel>();
            services.AddTransient<SecureNotesViewModel>();
            services.AddTransient<SecureFilesViewModel>();
            services.AddTransient<SettingsViewModel>();

            return services;
        }
    }
}
