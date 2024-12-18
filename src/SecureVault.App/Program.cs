using Microsoft.Extensions.DependencyInjection;
using SecureVault.Core.Interfaces;
using SecureVault.Core.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();

// Core services
builder.Services.AddScoped<IDatabaseService, DatabaseService>();
builder.Services.AddScoped<IEncryptionService, EncryptionService>();
builder.Services.AddScoped<ISecureFileStorageService, SecureFileStorageService>();
builder.Services.AddScoped<ITwoFactorAuthService, TwoFactorAuthService>();
builder.Services.AddScoped<IPasswordResetService, PasswordResetService>();
builder.Services.AddScoped<IMigrationService, MigrationService>();
builder.Services.AddScoped<IDataPortabilityService, DataPortabilityService>();
builder.Services.AddScoped<IBackupService, BackupService>();
builder.Services.AddScoped<IAuditLogService, AuditLogService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IBackupCredentialService, BackupCredentialService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();
