using System;
using System.Windows;
using System.Threading.Tasks;

namespace SecureVault.UI.Services
{
    public interface INotificationService
    {
        Task ShowSuccessAsync(string message);
        Task ShowErrorAsync(string message);
        Task ShowWarningAsync(string message);
        Task<bool> ShowConfirmationAsync(string message, string title = "Confirm Action");
    }

    public class NotificationService : INotificationService
    {
        public Task ShowSuccessAsync(string message)
        {
            return Application.Current.Dispatcher.InvokeAsync(() =>
            {
                MessageBox.Show(
                    message,
                    "Success",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }).Task;
        }

        public Task ShowErrorAsync(string message)
        {
            return Application.Current.Dispatcher.InvokeAsync(() =>
            {
                MessageBox.Show(
                    message,
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }).Task;
        }

        public Task ShowWarningAsync(string message)
        {
            return Application.Current.Dispatcher.InvokeAsync(() =>
            {
                MessageBox.Show(
                    message,
                    "Warning",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }).Task;
        }

        public Task<bool> ShowConfirmationAsync(string message, string title = "Confirm Action")
        {
            return Application.Current.Dispatcher.InvokeAsync(() =>
            {
                var result = MessageBox.Show(
                    message,
                    title,
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);
                return result == MessageBoxResult.Yes;
            }).Task;
        }
    }
}
