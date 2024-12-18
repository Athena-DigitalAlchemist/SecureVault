using System;
using System.Globalization;
using System.Windows.Data;

namespace SecureVault.UI.Converters
{
    public class StrengthToOffsetConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is int strength)
            {
                return strength / 100.0;
            }
            return 0;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
