from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import random

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "access_logs.csv"
SEED = 42
random.seed(SEED)

NORMAL_PATHS = [
    "/",
    "/shop",
    "/cart",
    "/checkout",
    "/my-account-2/",
    "/product/shirt",
    "/product/shoes",
    "/wp-content/uploads/banner.jpg",
]

SCAN_PATHS = [
    "/.env",
    "/wp-config.php",
    "/phpmyadmin",
    "/adminer.php",
    "/.git/config",
    "/etc/passwd",
    "/wp-admin/install.php",
    "/wp-json/wp/v2/users",
    "/xmlrpc.php",
]


def ip_for(window: int, client: int, anomaly: bool = False) -> str:
    first = 198 if anomaly else 203
    return f"{first}.51.{window % 250}.{(client % 240) + 1}"


def add_record(rows, window_id, ts, ip, method, path, status, response_ms, label, scenario):
    rows.append(
        {
            "window_id": window_id,
            "timestamp": ts.isoformat(),
            "ip": ip,
            "method": method,
            "path": path,
            "status_code": status,
            "response_time_ms": round(response_ms, 2),
            "label": label,
            "scenario": scenario,
        }
    )


def generate_normal_window(rows, window_id, start):
    clients = random.randint(3, 8)
    for client in range(clients):
        ip = ip_for(window_id, client)
        requests = random.randint(2, 14)
        for i in range(requests):
            path = random.choices(
                NORMAL_PATHS,
                weights=[18, 18, 8, 5, 6, 12, 12, 4],
                k=1,
            )[0]
            method = "POST" if path in ("/cart", "/checkout") and random.random() < 0.45 else "GET"
            status = random.choices([200, 200, 200, 302, 404, 403], weights=[55, 15, 10, 10, 7, 3], k=1)[0]
            response = max(20, random.gauss(180 if path == "/checkout" else 110, 35))
            add_record(
                rows,
                window_id,
                start + timedelta(seconds=random.randint(0, 299)),
                ip,
                method,
                path,
                status,
                response,
                0,
                "normal",
            )


def generate_attack_window(rows, window_id, start, scenario):
    ip = ip_for(window_id, 220, anomaly=True)

    if scenario == "brute_force":
        count = random.randint(35, 90)
        for _ in range(count):
            status = random.choices([401, 403, 200], weights=[75, 20, 5], k=1)[0]
            add_record(rows, window_id, start + timedelta(seconds=random.randint(0, 299)), ip,
                       "POST", "/wp-login.php", status, random.uniform(70, 220), 1, scenario)

    elif scenario == "scan":
        count = random.randint(45, 110)
        for i in range(count):
            path = random.choice(SCAN_PATHS)
            if i > len(SCAN_PATHS):
                path = f"/unknown-{i}.php"
            status = random.choices([404, 403, 200], weights=[70, 25, 5], k=1)[0]
            add_record(rows, window_id, start + timedelta(seconds=random.randint(0, 299)), ip,
                       "GET", path, status, random.uniform(35, 180), 1, scenario)

    elif scenario == "flood":
        count = random.randint(180, 420)
        for _ in range(count):
            add_record(rows, window_id, start + timedelta(seconds=random.randint(0, 299)), ip,
                       "GET", random.choice(NORMAL_PATHS[:3]), 200, random.uniform(20, 95), 1, scenario)

    elif scenario == "sensitive_probe":
        count = random.randint(25, 70)
        paths = ["/wp-json/wp/v2/users", "/xmlrpc.php", "/.env", "/wp-config.php", "/wp-admin/"]
        for _ in range(count):
            add_record(rows, window_id, start + timedelta(seconds=random.randint(0, 299)), ip,
                       random.choice(["GET", "POST"]), random.choice(paths),
                       random.choice([403, 404, 401]), random.uniform(40, 170), 1, scenario)


def main():
    rows = []
    base = datetime(2026, 7, 1, tzinfo=timezone.utc)

    for window_id in range(500):
        start = base + timedelta(minutes=5 * window_id)
        generate_normal_window(rows, window_id, start)

    scenarios = ["brute_force", "scan", "flood", "sensitive_probe"]
    for idx, scenario in enumerate(scenarios * 25, start=500):
        start = base + timedelta(minutes=5 * idx)
        generate_normal_window(rows, idx, start)
        generate_attack_window(rows, idx, start, scenario)

    df = pd.DataFrame(rows).sort_values(["window_id", "timestamp"])
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT, index=False)
    print(f"Dataset generado: {OUTPUT}")
    print(f"Registros: {len(df):,}")
    print(df["scenario"].value_counts().to_string())


if __name__ == "__main__":
    main()
