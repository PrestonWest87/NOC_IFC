import os
import joblib
from src.core.db import SessionLocal
from src.models.schema import Keyword

class HybridScorer:
    def __init__(self, model_path="src/ml_model.pkl"):
        self.model_path = model_path
        self.model = None

        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)

        with SessionLocal() as session:
            self.keywords = {k.word.lower(): k.weight for k in session.query(Keyword).all()}

    def score(self, text: str):
        text_lower = text.lower()
        reasons = []

        kw_score = 0.0
        for word, weight in self.keywords.items():
            if word in text_lower:
                kw_score += weight
                reasons.append(word)

        final_score = kw_score

        if self.model:
            prediction_probs = self.model.predict_proba([text_lower])[0]

            if len(prediction_probs) > 1:
                keep_prob = prediction_probs[1]
            else:
                keep_prob = 1.0 if self.model.classes_[0] == 1 else 0.0

            if keep_prob >= 0.75 and final_score < 50.0:
                final_score = max(final_score, 65.0)
                reasons.append(f"[AI] AI Boost: Hidden Threat Detected (Confidence: {int(keep_prob * 100)}%)")

            elif keep_prob <= 0.25 and final_score >= 50.0:
                noise_confidence = int((1 - keep_prob) * 100)
                penalty = final_score * 0.60
                final_score -= penalty
                reasons.append(f"[AI] AI Penalty: Context identified as Noise (Confidence: {noise_confidence}%)")

            elif keep_prob > 0.50 and final_score > 0:
                bonus = keep_prob * 10.0
                final_score += bonus
                reasons.append(f"[AI] AI Synergy Bonus (+{int(bonus)})")

        return min(final_score, 100.0), reasons

_SCORER_INSTANCE = None

def get_scorer():
    global _SCORER_INSTANCE
    if _SCORER_INSTANCE is None:
        _SCORER_INSTANCE = HybridScorer()
    return _SCORER_INSTANCE

def force_reload_scorer():
    global _SCORER_INSTANCE
    _SCORER_INSTANCE = HybridScorer()
