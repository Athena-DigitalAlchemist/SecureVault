using System;
using System.Globalization;
using System.Windows.Data;

namespace SecureVault.UI.Converters
{
    public class BoolToStringConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool boolValue && parameter is string param)
            {
                string[] options = param.Split('|');
                return boolValue ? options[0] : options.Length > 1 ? options[1] : string.Empty;
            }
            return string.Empty;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
