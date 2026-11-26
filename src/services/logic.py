"""Score articles with the configured keyword weights."""

import logging
from src.core.db import SessionLocal
from src.models.schema import Keyword

logger = logging.getLogger(__name__)

class KeywordScorer:
    """Score article text from a snapshot of persisted keyword weights."""

    def __init__(self):
        """Snapshot configured keyword weights for repeatable scoring within a process."""
        with SessionLocal() as session:
            self.keywords = {k.word.lower(): k.weight for k in session.query(Keyword).all()}
            logger.info("KeywordScorer: loaded %d keywords from database", len(self.keywords))

    def score(self, text: str):
        """Return a score capped at 100 and the matching keyword reasons."""
        text_lower = text.lower()
        reasons = []

        kw_score = 0.0
        for word, weight in self.keywords.items():
            if word in text_lower:
                kw_score += weight
                reasons.append(word)

        logger.debug("score: keyword_score=%.1f matched_keywords=%d", kw_score, len(reasons))
        logger.debug("score: keyword_score=%.1f matched_keywords=%d", kw_score, len(reasons))
        return min(kw_score, 100.0), reasons

_SCORER_INSTANCE = None

def get_scorer():
    """Return the lazily initialized process-local keyword scorer."""
    global _SCORER_INSTANCE
    if _SCORER_INSTANCE is None:
        logger.info("get_scorer: creating new KeywordScorer instance")
        _SCORER_INSTANCE = KeywordScorer()
    return _SCORER_INSTANCE

def force_reload_scorer():
    """Replace the process-local scorer so keyword changes take effect."""
    global _SCORER_INSTANCE
    logger.info("force_reload_scorer: reloading scorer with fresh keyword weights")
    _SCORER_INSTANCE = KeywordScorer()
