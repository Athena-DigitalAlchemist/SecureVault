using System;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureVault.UI.DependencyInjection;
using SecureVault.UI.ViewModels;
using SecureVault.UI.Views;

namespace SecureVault.UI
{
    public partial class App : Application
    {
        private IServiceProvider ServiceProvider { get; set; }

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            var services = new ServiceCollection();
            ConfigureServices(services);
            ServiceProvider = services.BuildServiceProvider();

            var mainWindow = new MainWindow
            {
                DataContext = ServiceProvider.GetRequiredService<MainWindowViewModel>()
            };

            mainWindow.Show();
        }

        private void ConfigureServices(IServiceCollection services)
        {
            // Add logging
            services.AddLogging(configure => configure.AddDebug());

            // Add SecureVault services
            services.AddSecureVaultServices();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            base.OnExit(e);

            if (ServiceProvider is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }
}
