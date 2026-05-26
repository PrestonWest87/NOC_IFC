import logging
from fastapi import APIRouter, Body
from typing import Any

from src import services as svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/llm", tags=["llm"])


@router.post("/executive-weather-brief")
def executive_weather_brief(data: dict[str, Any] = Body({})):
    from src.utils.llm import generate_executive_weather_brief
    from src.models.schema import SystemConfig
    from src.core.db import SessionLocal
    with SessionLocal() as db:
        config = db.query(SystemConfig).first()
    brief = generate_executive_weather_brief(
        data.get("analytics", {}),
        data.get("p1_at_risk", 0),
        config,
    )
    return {"brief": brief or "Unable to generate weather brief."}
