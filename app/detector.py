from __future__ import annotations

from pathlib import Path
import math

import joblib
import numpy as np
import pandas as pd

from app.features import FEATURE_COLUMNS, infer_behavior


MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "isolation_forest.joblib"


class ThreatDetector:
    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        if not model_path.exists():
            raise FileNotFoundError(
                f"No se encontró el modelo en {model_path}. "
                "Ejecuta: python scripts/train_model.py"
            )

        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        self.feature_columns = bundle["feature_columns"]
        self.score_center = float(bundle["score_center"])
        self.score_scale = float(bundle["score_scale"])

        if self.feature_columns != FEATURE_COLUMNS:
            raise ValueError("Las features del modelo no coinciden con la aplicación.")

    def _confidence(self, decision_score: float) -> float:
        # decision_function: valores menores a 0 son más anómalos.
        # Se transforma a [0,1] como indicador de confianza, no como probabilidad calibrada.
        z = -(decision_score - self.score_center) / max(self.score_scale, 1e-6)
        confidence = 1.0 / (1.0 + math.exp(-z))
        return float(np.clip(confidence, 0.0, 1.0))

    @staticmethod
    def _action(is_anomaly: bool, confidence: float) -> str:
        if is_anomaly and confidence >= 0.80:
            return "bloquear"
        if is_anomaly or confidence >= 0.60:
            return "alertar"
        return "ignorar"

    def analyze(self, features: pd.DataFrame) -> list[dict]:
        x = features[self.feature_columns]
        predictions = self.model.predict(x)
        decision_scores = self.model.decision_function(x)

        results: list[dict] = []
        for idx, (_, row) in enumerate(features.iterrows()):
            model_anomaly = bool(predictions[idx] == -1)

            # Guardia determinística para comportamiento volumétrico extremo.
            # Isolation Forest no siempre extrapola bien valores muy por encima
            # del máximo observado durante el entrenamiento.
            volume_guard = bool(row["request_count"] >= 100)

            is_anomaly = model_anomaly or volume_guard
            confidence = self._confidence(float(decision_scores[idx]))
            if volume_guard:
                confidence = max(confidence, 0.95)

            behavior, indicators = infer_behavior(row)
            if not is_anomaly:
                behavior = "comportamiento esperado"
                indicators = ["sin indicadores relevantes en el lote analizado"]

            results.append(
                {
                    "ip": row["ip"],
                    "threat_detected": is_anomaly,
                    "confidence": round(confidence, 4),
                    "action": self._action(is_anomaly, confidence),
                    "probable_behavior": behavior,
                    "indicators": indicators,
                }
            )

        return results
