using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecureVault.Core.Interfaces;
using System.IO;

namespace SecureVault.Tests.Integration
{
    public class TestWebApplicationFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureAppConfiguration((context, config) =>
            {
                var testDataDirectory = Path.Combine(
                    Path.GetTempPath(),
                    "SecureVaultTests",
                    Guid.NewGuid().ToString()
                );

                var testConfig = new Dictionary<string, string>
                {
                    ["DataDirectory"] = testDataDirectory,
                    ["SmtpSettings:Host"] = "localhost",
                    ["SmtpSettings:Port"] = "25",
                    ["SmtpSettings:Username"] = "test",
                    ["SmtpSettings:Password"] = "test",
                    ["SmtpSettings:FromEmail"] = "test@test.com",
                    ["SmtpSettings:FromName"] = "Test SecureVault",
                    ["SmtpSettings:EnableSsl"] = "false"
                };

                config.AddInMemoryCollection(testConfig);
            });

            builder.ConfigureServices(services =>
            {
                // Replace real email service with mock for testing
                services.AddScoped<IEmailService, MockEmailService>();
            });
        }

        public override ValueTask DisposeAsync()
        {
            var configuration = Services.GetRequiredService<IConfiguration>();
            var testDataDirectory = configuration["DataDirectory"];
            
            if (Directory.Exists(testDataDirectory))
            {
                Directory.Delete(testDataDirectory, true);
            }

            return base.DisposeAsync();
        }
    }

    public class MockEmailService : IEmailService
    {
        public Task SendEmailAsync(string to, string subject, string body)
        {
            // In a real test, you might want to store these values
            // to assert on them later
            return Task.CompletedTask;
        }
    }
}
