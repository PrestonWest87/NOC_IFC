import os
import joblib
from src.database import SessionLocal, Keyword

class HybridScorer:
    def __init__(self, model_path="src/ml_model.pkl"):
        # Explicitly set path to match the trainer
        self.model_path = model_path
        self.model = None
        
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        
        with SessionLocal() as session:
            self.keywords = {k.word.lower(): k.weight for k in session.query(Keyword).all()}

    def score(self, text: str):
        text_lower = text.lower()
        reasons = []
        
        # --- 1. Base Rule-Based Scoring (Keywords) ---
        kw_score = 0.0
        for word, weight in self.keywords.items():
            if word in text_lower:
                kw_score += weight
                reasons.append(word)

        final_score = kw_score

        # --- 2. Machine Learning Overlay (The Second Set of Eyes) ---
        if self.model:
            # Predict probability of Class 1 ("Keep / Important")
            prediction_probs = self.model.predict_proba([text_lower])[0]
            
            # Safely extract the probability percentage
            if len(prediction_probs) > 1:
                keep_prob = prediction_probs[1]
            else:
                keep_prob = 1.0 if self.model.classes_[0] == 1 else 0.0

            # --- 3. Dynamic Override Matrix ---
            
            # SCENARIO A: AI Spidey-Sense (Safety Net)
            # The keywords missed it (Score < 50), but the AI is highly confident (>75%) it's a threat.
            if keep_prob >= 0.75 and final_score < 50.0:
                final_score = max(final_score, 65.0) # Instantly bubble it to the dashboard
                reasons.append(f"🧠 AI Boost: Hidden Threat Detected (Confidence: {int(keep_prob * 100)}%)")
                
            # SCENARIO B: AI Spam Filter (Noise Reduction)
            # The keywords triggered (Score > 50), but the AI recognizes the context is harmless (<25% probability).
            elif keep_prob <= 0.25 and final_score >= 50.0:
                noise_confidence = int((1 - keep_prob) * 100)
                penalty = final_score * 0.60 # Strip 60% of the score away
                final_score -= penalty
                reasons.append(f"🧠 AI Penalty: Context identified as Noise (Confidence: {noise_confidence}%)")
                
            # SCENARIO C: Minor Synergy Adjustments
            # If the AI is mildly confident, give it a slight algorithmic bump.
            elif keep_prob > 0.50 and final_score > 0:
                bonus = keep_prob * 10.0
                final_score += bonus
                reasons.append(f"🧠 AI Synergy Bonus (+{int(bonus)})")

        return min(final_score, 100.0), reasons

def get_scorer():
    return HybridScorer()
