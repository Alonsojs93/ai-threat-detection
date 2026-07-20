from __future__ import annotations

from collections import defaultdict
from typing import Iterable

import pandas as pd

from app.schemas import AccessLog


FEATURE_COLUMNS = [
    "request_count",
    "failed_requests",
    "unauthorized_requests",
    "not_found_requests",
    "server_errors",
    "unique_paths",
    "login_attempts",
    "sensitive_path_hits",
    "suspicious_path_hits",
    "post_requests",
    "avg_response_time_ms",
    "max_response_time_ms",
    "error_ratio",
    "sensitive_ratio",
]

SENSITIVE_PATH_TOKENS = (
    "/wp-admin",
    "/wp-login.php",
    "/wp-json",
    "/xmlrpc.php",
    "/checkout",
)

SUSPICIOUS_PATH_TOKENS = (
    "/.env",
    "wp-config",
    "phpmyadmin",
    "/etc/passwd",
    "../",
    ".git",
    "/adminer",
)


def _contains_any(path: str, tokens: tuple[str, ...]) -> bool:
    path_lower = path.lower()
    return any(token in path_lower for token in tokens)


def build_features(records: Iterable[AccessLog]) -> pd.DataFrame:
    grouped: dict[str, list[AccessLog]] = defaultdict(list)
    for record in records:
        grouped[record.ip].append(record)

    rows: list[dict] = []

    for ip, ip_records in grouped.items():
        total = len(ip_records)
        failed = sum(r.status_code >= 400 for r in ip_records)
        unauthorized = sum(r.status_code in (401, 403) for r in ip_records)
        not_found = sum(r.status_code == 404 for r in ip_records)
        server_errors = sum(r.status_code >= 500 for r in ip_records)
        unique_paths = len({r.path for r in ip_records})
        login_attempts = sum("/wp-login.php" in r.path.lower() for r in ip_records)
        sensitive_hits = sum(_contains_any(r.path, SENSITIVE_PATH_TOKENS) for r in ip_records)
        suspicious_hits = sum(_contains_any(r.path, SUSPICIOUS_PATH_TOKENS) for r in ip_records)
        post_requests = sum(r.method == "POST" for r in ip_records)
        response_times = [r.response_time_ms for r in ip_records]

        rows.append(
            {
                "ip": ip,
                "request_count": total,
                "failed_requests": failed,
                "unauthorized_requests": unauthorized,
                "not_found_requests": not_found,
                "server_errors": server_errors,
                "unique_paths": unique_paths,
                "login_attempts": login_attempts,
                "sensitive_path_hits": sensitive_hits,
                "suspicious_path_hits": suspicious_hits,
                "post_requests": post_requests,
                "avg_response_time_ms": sum(response_times) / total,
                "max_response_time_ms": max(response_times),
                "error_ratio": failed / total,
                "sensitive_ratio": sensitive_hits / total,
            }
        )

    return pd.DataFrame(rows, columns=["ip", *FEATURE_COLUMNS])


def infer_behavior(row: pd.Series) -> tuple[str, list[str]]:
    indicators: list[str] = []

    if row["login_attempts"] >= 10 and row["unauthorized_requests"] >= 5:
        indicators.append("múltiples intentos fallidos contra wp-login.php")
        behavior = "posible fuerza bruta"
    elif row["unique_paths"] >= 20 and row["not_found_requests"] >= 10:
        indicators.append("alto número de rutas únicas con respuestas 404")
        behavior = "posible escaneo o enumeración"
    elif row["request_count"] >= 100:
        indicators.append("volumen de solicitudes atípicamente alto")
        behavior = "posible abuso automatizado o flood"
    elif row["suspicious_path_hits"] >= 3:
        indicators.append("sondeo repetido de rutas sensibles o archivos internos")
        behavior = "posible reconocimiento hostil"
    elif row["sensitive_path_hits"] >= 10 and row["error_ratio"] >= 0.4:
        indicators.append("acceso repetitivo a endpoints sensibles con alta tasa de error")
        behavior = "actividad anómala sobre endpoints sensibles"
    else:
        behavior = "anomalía estadística"

    if row["error_ratio"] >= 0.5:
        indicators.append("tasa de error HTTP elevada")
    if row["post_requests"] >= 10:
        indicators.append("cantidad elevada de solicitudes POST")
    if row["server_errors"] >= 3:
        indicators.append("múltiples respuestas 5xx")

    if not indicators:
        indicators.append("patrón multivariable fuera del comportamiento normal aprendido")

    return behavior, indicators
