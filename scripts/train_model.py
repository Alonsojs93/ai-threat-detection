from __future__ import annotations

from pathlib import Path
import json
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.features import FEATURE_COLUMNS, build_features
from app.schemas import AccessLog


DATA_PATH = ROOT / "data" / "access_logs.csv"
MODEL_PATH = ROOT / "models" / "isolation_forest.joblib"
METRICS_PATH = ROOT / "models" / "metrics.json"


def aggregate_dataset(df: pd.DataFrame) -> pd.DataFrame:
    feature_frames = []

    for window_id, group in df.groupby("window_id"):
        records = [
            AccessLog(
                timestamp=row.timestamp,
                ip=row.ip,
                method=row.method,
                path=row.path,
                status_code=int(row.status_code),
                response_time_ms=float(row.response_time_ms),
            )
            for row in group.itertuples(index=False)
        ]
        features = build_features(records)
        labels = (
            group.groupby("ip")["label"]
            .max()
            .rename("label")
            .reset_index()
        )
        scenarios = (
            group.groupby("ip")["scenario"]
            .agg(lambda values: "normal" if set(values) == {"normal"} else next(v for v in values if v != "normal"))
            .rename("scenario")
            .reset_index()
        )
        merged = features.merge(labels, on="ip").merge(scenarios, on="ip")
        merged["window_id"] = window_id
        feature_frames.append(merged)

    return pd.concat(feature_frames, ignore_index=True)


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError("Ejecuta primero: python scripts/generate_dataset.py")

    raw = pd.read_csv(DATA_PATH)
    dataset = aggregate_dataset(raw)

    normal = dataset[dataset["label"] == 0].copy()
    attack = dataset[dataset["label"] == 1].copy()

    # Se reserva 20% del tráfico normal para evaluación.
    # Los escenarios de ataque no participan en el entrenamiento.
    train_normal = normal.sample(frac=0.80, random_state=42)
    eval_normal = normal.drop(train_normal.index)

    # Entrenamiento solo con comportamiento normal.
    # Isolation Forest aprende la distribución esperada sin etiquetas de ataque.
    model = IsolationForest(
        n_estimators=300,
        contamination=0.01,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(train_normal[FEATURE_COLUMNS])

    normal_scores = model.decision_function(train_normal[FEATURE_COLUMNS])
    score_center = float(np.median(normal_scores))
    score_scale = float(max(np.std(normal_scores), 1e-6))

    evaluation = pd.concat(
        [
            eval_normal,
            attack,
        ],
        ignore_index=True,
    )
    model_predicted_attack = (model.predict(evaluation[FEATURE_COLUMNS]) == -1).astype(int)
    volume_guard = (evaluation["request_count"] >= 100).astype(int).to_numpy()
    predicted_attack = np.maximum(model_predicted_attack, volume_guard)
    y_true = evaluation["label"].astype(int).to_numpy()

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, predicted_attack, average="binary", zero_division=0
    )

    metrics = {
        "dataset_rows_raw": int(len(raw)),
        "entities_normal": int(len(normal)),
        "entities_attack": int(len(attack)),
        "training_normal_entities": int(len(train_normal)),
        "evaluation_normal_entities": int(len(eval_normal)),
        "evaluation_samples": int(len(evaluation)),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "confusion_matrix": confusion_matrix(y_true, predicted_attack).tolist(),
        "classification_report": classification_report(
            y_true,
            predicted_attack,
            target_names=["normal", "attack"],
            output_dict=True,
            zero_division=0,
        ),
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "feature_columns": FEATURE_COLUMNS,
            "score_center": score_center,
            "score_scale": score_scale,
        },
        MODEL_PATH,
    )
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"Modelo guardado: {MODEL_PATH}")
    print(json.dumps({k: metrics[k] for k in ["precision", "recall", "f1", "confusion_matrix"]}, indent=2))


if __name__ == "__main__":
    main()
