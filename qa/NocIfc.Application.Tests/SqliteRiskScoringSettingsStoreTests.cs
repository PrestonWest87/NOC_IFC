using NocIfc.Domain.Settings;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteRiskScoringSettingsStoreTests
{
    [Fact]
    public async Task ReadsAndPersistsOnlyProvidedRiskScoringColumns()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-risk-settings-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE system_config (
                        id INTEGER PRIMARY KEY, scoring_mode TEXT, baseline_override_cyber REAL,
                        baseline_override_phys REAL, cyber_criticality_override INTEGER,
                        cyber_lethality_override INTEGER, physical_criticality_override INTEGER,
                        physical_lethality_override INTEGER, internal_criticality_override INTEGER,
                        internal_lethality_override INTEGER, global_risk_offset INTEGER,
                        internal_risk_offset INTEGER, sys_countermeasures INTEGER, net_countermeasures INTEGER
                    );
                    INSERT INTO system_config VALUES (1, 'auto', 1, 2, 3, 4, 1, 2, 3, 4, 0, 1, 3, 3);
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteRiskScoringSettingsStore(connections);
            var before = Assert.IsType<RiskScoringSettings>(await store.GetAsync(CancellationToken.None));
            Assert.Equal("auto", before.ScoringMode);
            var update = new RiskScoringSettings("hybrid", 4.5, null, null, null, null, null, null, null, -2, null, 2, null);
            await store.UpdateAsync(update, CancellationToken.None);

            var after = Assert.IsType<RiskScoringSettings>(await store.GetAsync(CancellationToken.None));
            Assert.Equal("hybrid", after.ScoringMode);
            Assert.Equal(4.5, after.BaselineOverrideCyber);
            Assert.Equal(2d, after.BaselineOverridePhys);
            Assert.Equal(-2, after.GlobalRiskOffset);
            Assert.Equal(2, after.SysCountermeasures);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
