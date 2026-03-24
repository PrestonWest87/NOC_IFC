import pandas as pd
import joblib
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sqlalchemy.orm import Session
from src.database import SessionLocal, Article

MODEL_PATH = "src/ml_model.pkl"

def train():
    with SessionLocal() as session:
        # 1. Fetch Training Data
        # human_feedback: 1 = Dismiss (Noise), 2 = Confirm (Keep)
        query = session.query(Article.summary, Article.title, Article.human_feedback)\
            .filter(Article.human_feedback.in_([1, 2]))
        
        df = pd.read_sql(query.statement, session.bind)

    if len(df) < 10:
        print(f"⚠️ Not enough training data! You have {len(df)} labels. Please review at least 10 articles in the UI.")
        return

    print(f"🧠 Training Advanced ML Model on {len(df)} curated articles...")

    # 2. Preprocessing
    # Combine Title + Summary for deep context, force lowercase
    df['text'] = (df['title'] + " " + df['summary']).str.lower()
    
    # Map labels: 1 (Dismiss) -> 0 (Noise), 2 (Confirm) -> 1 (Important)
    y = df['human_feedback'].map({1: 0, 2: 1})
    X = df['text']

    # 3. Build Advanced Pipeline
    # - ngram_range=(1, 2): Allows the model to learn phrases like "data breach" or "buffer overflow"
    # - LogisticRegression: Provides highly accurate probability scaling
    # - class_weight='balanced': Prevents the model from just guessing "Noise" every time
    model = make_pipeline(
        TfidfVectorizer(stop_words='english', ngram_range=(1, 2), max_df=0.9, min_df=1),
        LogisticRegression(class_weight='balanced', max_iter=1000)
    )

    # 4. Train
    model.fit(X, y)

    # 5. Save the "Brain"
    joblib.dump(model, MODEL_PATH)
    print(f"✅ Advanced NOC ML Model successfully saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()
