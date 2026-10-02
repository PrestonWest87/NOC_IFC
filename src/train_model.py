import logging
import os
import tempfile
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from src.database import SessionLocal, Article
from src.core.paths import ml_model_path

logger = logging.getLogger(__name__)
MODEL_PATH = str(ml_model_path())

def train():
    with SessionLocal() as session:
        # 1. Fetch Training Data
        # human_feedback: 1 = Dismiss (Noise), 2 = Confirm (Keep)
        rows = session.query(Article.summary, Article.title, Article.human_feedback)\
            .filter(Article.human_feedback.in_([1, 2])).all()

    if len(rows) < 10:
        logger.warning("Not enough training data! You have %s labels. Please review at least 10 articles in the UI.", len(rows))
        return

    logger.info("Training Advanced ML Model on %s curated articles...", len(rows))

    # Map labels: 1 (Dismiss) -> 0 (Noise), 2 (Confirm) -> 1 (Important)
    # Keep the exact same training data contract without building a DataFrame.
    X = [f"{title or ''} {summary or ''}".lower() for summary, title, _ in rows]
    y = [0 if feedback == 1 else 1 for _summary, _title, feedback in rows]

    # 3. Build Advanced Pipeline
    # - ngram_range=(1, 2): Allows the model to learn phrases like "data breach" or "buffer overflow"
    # - LogisticRegression: Provides highly accurate probability scaling
    # - class_weight='balanced': Prevents the model from just guessing "Noise" every time
    model = make_pipeline(
        TfidfVectorizer(stop_words='english', ngram_range=(1, 2), max_df=0.9, min_df=3, max_features=50000),
        LogisticRegression(class_weight='balanced', max_iter=1000)
    )

    # 4. Train
    model.fit(X, y)

    # 5. Save the "Brain"
    from pathlib import Path

    model_path = Path(MODEL_PATH)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{model_path.name}.", suffix=".tmp", dir=model_path.parent
    )
    os.close(descriptor)
    try:
        joblib.dump(model, temporary_path)
        os.replace(temporary_path, model_path)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)
    logger.info("Advanced NOC ML Model successfully saved to %s", MODEL_PATH)

if __name__ == "__main__":
    train()
