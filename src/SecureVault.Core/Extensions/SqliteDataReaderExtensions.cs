using Microsoft.Data.Sqlite;

namespace SecureVault.Core.Extensions
{
    public static class SqliteDataReaderExtensions
    {
        public static string GetStringSafe(this SqliteDataReader reader, string columnName)
        {
            var ordinal = reader.GetOrdinal(columnName);
            return reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);
        }

        public static int GetOrdinalSafe(this SqliteDataReader reader, string columnName)
        {
            return reader.GetOrdinal(columnName);
        }
    }
}