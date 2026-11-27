using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Threat;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteKeywordAnalysisStore(SqliteConnectionFactory connections) : IKeywordAnalysisStore
{
    public async Task<KeywordAnalysisOverview> GetOverviewAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        var totalKeywords = await CountAsync(connection, "SELECT COUNT(*) FROM keywords", cancellationToken);
        var totalArticles = await CountAsync(connection, "SELECT COUNT(*) FROM articles", cancellationToken);
        double averageWeight = 0;
        var maximumWeight = 0;
        var minimumWeight = 0;
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT COALESCE(AVG(weight), 0), COALESCE(MAX(weight), 0), COALESCE(MIN(weight), 0) FROM keywords";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                averageWeight = reader.GetDouble(0);
                maximumWeight = reader.GetInt32(1);
                minimumWeight = reader.GetInt32(2);
            }
        }

        var usedWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var articlesWithKeywords = 0;
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT keywords_found FROM articles";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var words = ReadKeywords(reader, 0);
                if (words.Length == 0) continue;
                articlesWithKeywords++;
                foreach (var word in words) usedWords.Add(word);
            }
        }

        return new KeywordAnalysisOverview(
            totalKeywords, totalArticles, Math.Round(averageWeight, 1), maximumWeight, minimumWeight,
            usedWords.Count, totalKeywords - usedWords.Count, articlesWithKeywords, totalArticles - articlesWithKeywords);
    }

    public async Task<IReadOnlyList<KeywordAnalysisStat>> GetKeywordStatsAsync(
        string sortBy,
        bool descending,
        string search,
        int limit,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        var keywords = new List<(int Id, string Word, int Weight)>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT id, word, weight FROM keywords ORDER BY id";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var word = reader.IsDBNull(1) ? "" : reader.GetString(1);
                if (search.Length > 0 && !word.Contains(search, StringComparison.OrdinalIgnoreCase)) continue;
                keywords.Add((reader.GetInt32(0), word, reader.IsDBNull(2) ? 0 : reader.GetInt32(2)));
            }
        }

        var triggerCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT keywords_found FROM articles";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                foreach (var word in ReadKeywords(reader, 0))
                {
                    triggerCounts[word] = triggerCounts.GetValueOrDefault(word) + 1;
                }
            }
        }

        var weightsByWord = keywords.GroupBy(keyword => keyword.Word, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Select(item => item.Weight).ToArray(), StringComparer.OrdinalIgnoreCase);
        var results = keywords.Select(keyword =>
        {
            var triggers = triggerCounts.GetValueOrDefault(keyword.Word);
            var contribution = triggers == 0
                ? 0
                : Math.Round(weightsByWord[keyword.Word].Average(weight => (double)weight * triggers), 1);
            return new KeywordAnalysisStat(keyword.Id, keyword.Word, keyword.Weight, triggers, contribution);
        });

        IOrderedEnumerable<KeywordAnalysisStat> ordered = (sortBy, descending) switch
        {
            ("weight", true) => results.OrderByDescending(item => item.Weight),
            ("weight", false) => results.OrderBy(item => item.Weight),
            ("avg_score_contribution", true) => results.OrderByDescending(item => item.AverageScoreContribution),
            ("avg_score_contribution", false) => results.OrderBy(item => item.AverageScoreContribution),
            ("trigger_count", true) => results.OrderByDescending(item => item.TriggerCount),
            _ => results.OrderBy(item => item.TriggerCount),
        };
        return ordered.Take(limit).ToArray();
    }

    public async Task<IReadOnlyList<KeywordCategoryDistribution>> GetCategoryDistributionAsync(
        int days,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        const string category = "CASE WHEN category IS NULL OR category = '' THEN 'General' ELSE category END";
        command.CommandText = $"""
            SELECT {category}, COUNT(*), COALESCE(AVG(COALESCE(score, 0)), 0)
            FROM articles
            WHERE ($cutoff IS NULL OR published_date >= $cutoff)
            GROUP BY {category}
            ORDER BY COUNT(*) DESC
            """;
        command.Parameters.AddWithValue("$cutoff", Cutoff(days));
        var categories = new List<(string Category, int Count, double AverageScore)>();
        var total = 0;
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                var count = reader.GetInt32(1);
                total += count;
                categories.Add((reader.GetString(0), count, Math.Round(reader.GetDouble(2), 1)));
            }
        }
        return categories.Select(item => new KeywordCategoryDistribution(
            item.Category, item.Count, item.AverageScore,
            total == 0 ? 0 : Math.Round(item.Count / (double)total * 100, 1))).ToArray();
    }

    public async Task<IReadOnlyList<KeywordAnalysisTimelinePoint>> GetTimelineAsync(
        string keyword,
        int days,
        string interval,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT published_date, score, keywords_found
            FROM articles
            WHERE published_date IS NOT NULL AND ($cutoff IS NULL OR published_date >= $cutoff)
            ORDER BY published_date
            """;
        command.Parameters.AddWithValue("$cutoff", Cutoff(days));
        var points = new SortedDictionary<string, TimelineCounts>(StringComparer.Ordinal);
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                var published = ReadDateTime(reader, 0);
                if (published is null) continue;
                var key = interval == "week" ? WeekKey(published.Value) : published.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                if (!points.TryGetValue(key, out var counts)) counts = new TimelineCounts();
                var words = ReadKeywords(reader, 2);
                counts.Total++;
                counts.Score += reader.IsDBNull(1) ? 0 : reader.GetDouble(1);
                if (keyword.Length == 0 ? words.Length > 0 : words.Contains(keyword, StringComparer.OrdinalIgnoreCase))
                {
                    counts.Matched++;
                }
                points[key] = counts;
            }
        }

        return points.Select(pair => new KeywordAnalysisTimelinePoint(
            pair.Key,
            pair.Value.Total,
            pair.Value.Matched,
            pair.Value.Total == 0 ? 0 : Math.Round(pair.Value.Matched / (double)pair.Value.Total * 100, 1),
            pair.Value.Total == 0 ? 0 : Math.Round(pair.Value.Score / pair.Value.Total, 1))).ToArray();
    }

    public async Task<IReadOnlyList<KeywordAnalysisArticle>> GetKeywordArticlesAsync(
        string keyword,
        int limit,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, title, source, category, score, published_date, keywords_found
            FROM articles
            WHERE keywords_found IS NOT NULL
            ORDER BY published_date DESC
            """;
        var articles = new List<KeywordAnalysisArticle>(limit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken) && articles.Count < limit)
        {
            var words = ReadKeywords(reader, 6);
            if (!words.Contains(keyword, StringComparer.OrdinalIgnoreCase)) continue;
            articles.Add(new KeywordAnalysisArticle(
                reader.GetInt32(0), ReadString(reader, 1), ReadString(reader, 2), ReadString(reader, 3),
                ReadDouble(reader, 4), ReadDateTime(reader, 5), words));
        }
        return articles;
    }

    public async Task<IReadOnlyList<KeywordScoreBucket>> GetScoreDistributionAsync(
        int days,
        int bucketSize,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT score, category
            FROM articles
            WHERE ($cutoff IS NULL OR published_date >= $cutoff)
            """;
        command.Parameters.AddWithValue("$cutoff", Cutoff(days));
        var labels = new List<string>();
        var buckets = new Dictionary<string, ScoreBucketCounts>(StringComparer.Ordinal);
        for (var start = 0; start <= 100; start += bucketSize)
        {
            var label = $"{start}-{Math.Min(start + bucketSize - 1, 100)}";
            labels.Add(label);
            buckets[label] = new ScoreBucketCounts();
        }

        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                var score = reader.IsDBNull(0) ? 0 : (int)reader.GetDouble(0);
                var start = Math.Min(score / bucketSize * bucketSize, 100 - bucketSize);
                var label = $"{start}-{Math.Min(start + bucketSize - 1, 100)}";
                if (!buckets.TryGetValue(label, out var bucket)) continue;
                bucket.Count++;
                var category = ReadString(reader, 1);
                category = string.IsNullOrEmpty(category) ? "General" : category;
                bucket.Categories[category] = bucket.Categories.GetValueOrDefault(category) + 1;
            }
        }

        return labels.Select(label =>
        {
            var bucket = buckets[label];
            var topCategory = bucket.Categories.Count == 0
                ? "N/A"
                : bucket.Categories.OrderByDescending(item => item.Value).First().Key;
            return new KeywordScoreBucket(label, bucket.Count, topCategory);
        }).ToArray();
    }

    public async Task<KeywordCategoryMatrix> GetCategoryKeywordMatrixAsync(int topN, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT category, keywords_found FROM articles ORDER BY id";
        var categoryCounts = new SortedDictionary<string, Dictionary<string, int>>(StringComparer.Ordinal);
        var keywordCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        var keywordOrder = new List<string>();
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                var category = ReadString(reader, 0);
                category = string.IsNullOrEmpty(category) ? "General" : category;
                var words = ReadKeywords(reader, 1);
                if (words.Length == 0) continue;
                if (!categoryCounts.TryGetValue(category, out var counts))
                {
                    counts = new Dictionary<string, int>(StringComparer.Ordinal);
                    categoryCounts[category] = counts;
                }
                foreach (var word in words)
                {
                    var normalized = word.ToLowerInvariant();
                    counts[normalized] = counts.GetValueOrDefault(normalized) + 1;
                    if (!keywordCounts.ContainsKey(normalized)) keywordOrder.Add(normalized);
                    keywordCounts[normalized] = keywordCounts.GetValueOrDefault(normalized) + 1;
                }
            }
        }

        var topKeywords = keywordOrder.OrderByDescending(word => keywordCounts[word]).Take(topN).ToArray();
        var rows = new List<IReadOnlyDictionary<string, object?>>();
        foreach (var (category, counts) in categoryCounts)
        {
            var row = new Dictionary<string, object?>(StringComparer.Ordinal) { ["category"] = category };
            foreach (var keyword in topKeywords) row[keyword] = counts.GetValueOrDefault(keyword);
            row["total"] = counts.Values.Sum();
            rows.Add(row);
        }
        return new KeywordCategoryMatrix(categoryCounts.Keys.ToArray(), topKeywords, rows);
    }

    public async Task<KeywordCategoryDetails> GetCategoryDetailsAsync(
        string category,
        int days,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, title, source, score, published_date, keywords_found
            FROM articles
            WHERE category = $category AND ($cutoff IS NULL OR published_date >= $cutoff)
            ORDER BY published_date DESC
            LIMIT 200
            """;
        command.Parameters.AddWithValue("$category", category);
        command.Parameters.AddWithValue("$cutoff", Cutoff(days));
        var articles = new List<KeywordRecentArticle>();
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                articles.Add(new KeywordRecentArticle(
                    reader.GetInt32(0), ReadString(reader, 1), ReadString(reader, 2),
                    ReadDouble(reader, 3), ReadDateTime(reader, 4), ReadKeywords(reader, 5)));
            }
        }

        var keywordCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        var sourceCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        var totalScore = 0d;
        foreach (var article in articles)
        {
            totalScore += article.Score ?? 0;
            var source = string.IsNullOrEmpty(article.Source) ? "Unknown" : article.Source;
            sourceCounts[source] = sourceCounts.GetValueOrDefault(source) + 1;
            foreach (var word in article.KeywordsFound)
            {
                var normalized = word.ToLowerInvariant();
                keywordCounts[normalized] = keywordCounts.GetValueOrDefault(normalized) + 1;
            }
        }

        return new KeywordCategoryDetails(
            category,
            articles.Count,
            articles.Count == 0 ? 0 : Math.Round(totalScore / articles.Count, 1),
            keywordCounts.OrderByDescending(item => item.Value).Take(15)
                .Select(item => new KeywordOccurrence(item.Key, item.Value)).ToArray(),
            sourceCounts.OrderByDescending(item => item.Value).Take(10)
                .Select(item => new KeywordSourceCount(item.Key, item.Value)).ToArray(),
            articles.Take(50).ToArray());
    }

    public async Task<IReadOnlyList<KeywordArticleForRecategorization>> GetRecategorizationBatchAsync(
        int afterId,
        int limit,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, title, summary, category FROM articles WHERE id > $after_id ORDER BY id LIMIT $limit";
        command.Parameters.AddWithValue("$after_id", afterId);
        command.Parameters.AddWithValue("$limit", limit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var batch = new List<KeywordArticleForRecategorization>();
        while (await reader.ReadAsync(cancellationToken))
        {
            batch.Add(new KeywordArticleForRecategorization(
                reader.GetInt32(0), ReadString(reader, 1), ReadString(reader, 2), ReadString(reader, 3)));
        }
        return batch;
    }

    public async Task<int> UpdateArticleCategoriesAsync(
        IReadOnlyList<KeywordCategoryUpdate> updates,
        CancellationToken cancellationToken)
    {
        if (updates.Count == 0) return 0;
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var changed = 0;
        foreach (var update in updates)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "UPDATE articles SET category = $category WHERE id = $id AND (category IS NULL OR category != $category)";
            command.Parameters.AddWithValue("$category", update.Category);
            command.Parameters.AddWithValue("$id", update.Id);
            changed += await command.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
        return changed;
    }

    private static async Task<int> CountAsync(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
    }

    private static object Cutoff(int days) => days == 0
        ? DBNull.Value
        : FormatDate(DateTime.UtcNow.AddDays(-days));

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static string[] ReadKeywords(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal)) return [];
        try
        {
            using var document = JsonDocument.Parse(reader.GetString(ordinal));
            if (document.RootElement.ValueKind != JsonValueKind.Array) return [];
            return document.RootElement.EnumerateArray()
                .Where(item => item.ValueKind == JsonValueKind.String)
                .Select(item => item.GetString() ?? "")
                .ToArray();
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static double? ReadDouble(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetDouble(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal)
            ? null
            : DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);

    private static string WeekKey(DateTime date)
    {
        var firstDay = new DateTime(date.Year, 1, 1);
        var firstSundayOffset = ((int)DayOfWeek.Sunday - (int)firstDay.DayOfWeek + 7) % 7;
        var dayIndex = date.DayOfYear - 1;
        var week = dayIndex < firstSundayOffset ? 0 : (dayIndex - firstSundayOffset) / 7 + 1;
        return $"{date.Year}-W{week:00}";
    }

    private sealed class TimelineCounts
    {
        public int Total { get; set; }
        public int Matched { get; set; }
        public double Score { get; set; }
    }

    private sealed class ScoreBucketCounts
    {
        public int Count { get; set; }
        public Dictionary<string, int> Categories { get; } = new(StringComparer.Ordinal);
    }
}
