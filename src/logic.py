import os
import joblib
from src.database import SessionLocal, Keyword

class HybridScorer:
    def __init__(self, model_path="ml_model.pkl"):
        self.model_path = model_path
        self.model = None
        
        # Load the ML model if you have trained one
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        
        # Load the strict keywords from the database
        session = SessionLocal()
        self.keywords = {k.word.lower(): k.weight for k in session.query(Keyword).all()}
        session.close()

    def score(self, text: str):
        text_lower = text.lower()
        reasons = []
        
        # --- 1. Rule-Based Scoring (Keywords) ---
        kw_score = 0
        for word, weight in self.keywords.items():
            if word in text_lower:
                kw_score += weight
                reasons.append(word)

        # --- 2. Machine Learning Scoring (AI) ---
        ml_score = 0.0
        if self.model:
            prediction_prob = self.model.predict_proba([text])[0]
            
            # Safely check how many classes the model knows
            if len(prediction_prob) > 1:
                ml_score = float(prediction_prob[1]) * 100.0
            else:
                if self.model.classes_[0] == 2: # 2 means "Keep"
                    ml_score = 100.0
                else:
                    ml_score = 0.0
            
            # If the AI strongly believes this is important, flag it
            if ml_score >= 45:
                reasons.append(f"AI Safety Net ({int(ml_score)}%)")

        # --- 3. Hybrid Fusion ---
        # Take the highest score. If keywords miss it but AI catches it, it still bubbles up!
        final_score = max(float(kw_score), ml_score)
        
        return final_score, reasons

def get_scorer():
    return HybridScorer()