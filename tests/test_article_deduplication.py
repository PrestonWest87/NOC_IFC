import unittest
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.models.schema import Article, Base
from src.services import deduplicate_articles


class ArticleDeduplicationTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, autoflush=False)

    def tearDown(self):
        self.engine.dispose()

    def test_rapidfuzz_keeps_existing_title_duplicate_threshold(self):
        now = datetime.utcnow()
        with self.session_factory() as session:
            session.add_all([
                Article(
                    title="Ransomware attack disrupts Arkansas power grid",
                    link="https://same.example/story-1", published_date=now,
                ),
                Article(
                    title="Ransomware attack disrupts Arkansas power grids",
                    link="https://same.example/story-2", published_date=now,
                ),
                Article(
                    title="Severe weather advisory affects coastal utility sites",
                    link="https://same.example/story-3", published_date=now,
                ),
            ])
            session.commit()

            removed = deduplicate_articles(session)

            self.assertEqual(removed, 1)
            self.assertEqual(session.query(Article).count(), 2)


if __name__ == "__main__":
    unittest.main()
