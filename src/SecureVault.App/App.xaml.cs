using System.IO;
using System.Windows;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Services;
using Serilog;

namespace SecureVault.App
{
    public partial class App : Application
    {
        private IServiceProvider _serviceProvider;
        private IConfiguration _configuration;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Initialize configuration
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

            _configuration = builder.Build();

            // Initialize logging
            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(_configuration)
                .CreateLogger();

            // Configure services
            var services = new ServiceCollection();
            ConfigureServices(services);

            _serviceProvider = services.BuildServiceProvider();

            // Initialize database
            var dbService = _serviceProvider.GetRequiredService<IDatabaseService>();
            dbService.InitializeDatabaseAsync().Wait();

            // Show main window
            var mainWindow = _serviceProvider.GetRequiredService<MainWindow>();
            mainWindow.Show();
        }

        private void ConfigureServices(IServiceCollection services)
        {
            // Configuration
            services.AddSingleton(_configuration);

            // Core services
            services.AddSingleton<IDatabaseService, DatabaseService>();
            services.AddSingleton<IEncryptionService>(sp =>
            {
                var config = sp.GetRequiredService<IConfiguration>();
                var iterations = config.GetValue<int>("Security:IterationCount");
                var keySize = config.GetValue<int>("Security:KeySize");
                var saltSize = config.GetValue<int>("Security:DefaultSaltSize");

                var masterKey = config.GetValue<string>("Security:DefaultMasterKey") ?? "DefaultMasterKey123!@#";
                var salt = new byte[saltSize];

                return new EncryptionService(masterKey, salt, iterations, keySize);
            });
            services.AddSingleton<IAuthenticationService, AuthenticationService>();
            services.AddSingleton<IKeyManagementService, KeyManagementService>();
            services.AddSingleton<IPasswordService, PasswordService>();
            services.AddSingleton<ISecureNoteService, SecureNoteService>();
            services.AddSingleton<ISecureFileService, SecureFileService>();
            services.AddSingleton<IBackupService, BackupService>();
            services.AddSingleton<ISettingsService, SettingsService>();

            // UI Services
            services.AddSingleton<IDialogService, DialogService>();
            services.AddSingleton<INavigationService, NavigationService>();

            // ViewModels
            services.AddTransient<MainWindowViewModel>();
            services.AddTransient<LoginViewModel>();
            services.AddTransient<DashboardViewModel>();
            services.AddTransient<PasswordListViewModel>();
            services.AddTransient<PasswordEditViewModel>();
            services.AddTransient<SecureNotesViewModel>();
            services.AddTransient<SecureFilesViewModel>();
            services.AddTransient<SettingsViewModel>();

            // Views
            services.AddTransient<MainWindow>();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            Log.CloseAndFlush();
            base.OnExit(e);
        }
    }
}
