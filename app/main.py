from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.detector import ThreatDetector
from app.features import build_features
from app.schemas import AnalyzeRequest, AnalyzeResponse


detector: ThreatDetector | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global detector
    detector = ThreatDetector()
    yield
    detector = None


app = FastAPI(
    title="AI Threat Detection API",
    version="1.0.0",
    description=(
        "Módulo de detección de comportamiento anómalo en lotes de registros "
        "de acceso HTTP mediante Isolation Forest."
    ),
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    assert detector is not None, "El detector no fue inicializado."

    features = build_features(payload.records)
    results = detector.analyze(features)

    threats = [item for item in results if item["threat_detected"]]
    max_confidence = max(item["confidence"] for item in results)

    if any(item["action"] == "bloquear" for item in results):
        overall_action = "bloquear"
    elif any(item["action"] == "alertar" for item in results):
        overall_action = "alertar"
    else:
        overall_action = "ignorar"

    return AnalyzeResponse(
        threat_detected=bool(threats),
        confidence=max_confidence,
        action=overall_action,
        records_analyzed=len(payload.records),
        entities_analyzed=len(results),
        results=results,
    )
