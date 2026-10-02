import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.api.routes import keyword_analysis
from src.models.schema import Article, Base, Keyword


class KeywordAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        now = datetime.utcnow()
        with self.session_factory() as session:
            session.add_all([
                Keyword(word="ransomware", weight=90),
                Keyword(word="breach", weight=85),
            ])
            session.add_all([
                Article(
                    title="First cyber story", source="Wire A", category="Cyber",
                    score=80, published_date=now - timedelta(hours=3),
                    keywords_found=["ransomware", "breach"], summary="first",
                ),
                Article(
                    title="Physical story", source="Wire B", category="Physical",
                    score=40, published_date=now - timedelta(hours=2),
                    keywords_found=[], summary="second",
                ),
                Article(
                    title="Recent cyber story", source="Wire A", category="Cyber",
                    score=60, published_date=now - timedelta(hours=1),
                    keywords_found=["breach"], summary="third",
                ),
            ])
            session.commit()

    def tearDown(self):
        self.engine.dispose()

    def test_analytics_preserve_output_shapes_with_projected_rows(self):
        with patch("src.core.db.SessionLocal", self.session_factory):
            overview = keyword_analysis.keyword_overview()
            stats = keyword_analysis.keyword_stats(
                sort_by="trigger_count", order="desc", search="", limit=10
            )
            distribution = keyword_analysis.category_distribution(days=0)
            timeline = keyword_analysis.keyword_timeline(
                keyword="breach", days=7, interval="day"
            )
            matching_articles = keyword_analysis.keyword_articles(keyword="breach", limit=1)
            details = keyword_analysis.category_details(category="Cyber", days=0)
            matrix = keyword_analysis.category_keyword_matrix(top_n=2)

        self.assertEqual(overview["total_articles"], 3)
        self.assertEqual(overview["articles_with_keywords"], 2)
        self.assertEqual(overview["keywords_used"], 2)
        self.assertEqual(stats[0]["word"], "breach")
        self.assertEqual(stats[0]["trigger_count"], 2)
        cyber = next(row for row in distribution if row["category"] == "Cyber")
        self.assertEqual(cyber["count"], 2)
        self.assertEqual(cyber["avg_score"], 70.0)
        self.assertEqual(timeline[0]["matched_articles"], 2)
        self.assertEqual(matching_articles[0]["title"], "Recent cyber story")
        self.assertEqual(details["total_articles"], 2)
        self.assertEqual(matrix["keywords"], ["breach", "ransomware"])

    def test_recategorize_updates_in_bounded_batches_and_returns_counts(self):
        with patch("src.core.db.SessionLocal", self.session_factory), patch(
            "src.services.categorizer.categorize_text", return_value="Reviewed"
        ):
            result = keyword_analysis.recategorize_all()

        self.assertEqual(result, {"status": "ok", "total": 3, "changed": 3})
        with self.session_factory() as session:
            self.assertEqual(session.query(Article.category).distinct().all(), [("Reviewed",)])


if __name__ == "__main__":
    unittest.main()
