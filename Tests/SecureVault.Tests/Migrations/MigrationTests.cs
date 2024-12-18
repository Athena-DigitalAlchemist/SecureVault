using SecureVault.Core.Services;

namespace SecureVault.Tests.Migrations
{
    [TestClass]
    public class MigrationTests
    {
        private IDatabaseService _databaseService;
        private string _testDbPath;

        [TestInitialize]
        public void Setup()
        {
            _testDbPath = Path.Combine(Path.GetTempPath(), "securevault_test.db");
            _databaseService = new DatabaseService(_testDbPath);
        }

        [TestMethod]
        public async Task ModifiedAtToLastModified_Migration_ShouldSucceed()
        {
            // Arrange
            var migrationScript = await File.ReadAllTextAsync(
                "../../src/SecureVault.Core/Data/Migrations/20241211_UpdateModifiedAtToLastModified.sql");

            // Act
            await _databaseService.ExecuteRawSqlAsync(migrationScript);

            // Assert
            var hasLastModified = await _databaseService.ColumnExistsAsync("Notes", "LastModified");
            var hasModifiedAt = await _databaseService.ColumnExistsAsync("Notes", "ModifiedAt");

            Assert.IsTrue(hasLastModified, "LastModified column should exist");
            Assert.IsFalse(hasModifiedAt, "ModifiedAt column should not exist");
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (File.Exists(_testDbPath))
            {
                File.Delete(_testDbPath);
            }
        }
    }
}
