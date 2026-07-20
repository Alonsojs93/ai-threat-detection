# Módulo de detección de amenazas con IA

Backend en Python para analizar lotes de registros de acceso HTTP y detectar comportamientos anómalos mediante **Isolation Forest**, complementado con una guardia determinística para volumen extremo. El proyecto fue desarrollado como bonus opcional del challenge de ciberseguridad.

## 1. Objetivo

El servicio recibe un lote de registros mediante `POST /analyze`, agrupa la actividad por dirección IP, genera variables de comportamiento y evalúa cada entidad con un modelo de detección de anomalías.

La respuesta indica:

- si existe una amenaza detectada;
- un indicador de confianza entre `0` y `1`;
- una acción sugerida: `bloquear`, `alertar` o `ignorar`;
- el detalle de las entidades analizadas y los principales indicadores observados.

> **Nota sobre `confidence`:** el valor no representa una probabilidad estadística calibrada. Es un indicador normalizado derivado de la distancia del registro agregado respecto al comportamiento normal aprendido por Isolation Forest.

---

## 2. Arquitectura

```text
Cliente
  |
  | POST /analyze
  v
FastAPI
  |
  v
Validación de entrada (Pydantic)
  |
  v
Feature Engineering por IP
  |
  v
Isolation Forest
  |
  v
Motor de decisión
  |
  +--> bloquear
  +--> alertar
  +--> ignorar
```

### Componentes

```text
ai-threat-detection/
├── app/
│   ├── main.py          # API REST
│   ├── schemas.py       # Esquemas de entrada y salida
│   ├── features.py      # Extracción de variables
│   └── detector.py      # Inferencia y decisión
├── scripts/
│   ├── generate_dataset.py
│   └── train_model.py
├── data/
│   └── access_logs.csv
├── models/
│   ├── isolation_forest.joblib
│   └── metrics.json
├── tests/
│   └── test_api.py
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## 3. Decisiones técnicas

### Isolation Forest

Se eligió **Isolation Forest** porque el problema corresponde a detección de anomalías y no requiere disponer de un conjunto de ataques exhaustivamente etiquetado para entrenar el modelo.

El entrenamiento se realiza exclusivamente con comportamiento normal sintético. El modelo aprende la distribución esperada y asigna una puntuación de anomalía a nuevas observaciones.

Ventajas para este caso:

- adecuado para detección no supervisada;
- bajo costo computacional;
- inferencia rápida;
- permite identificar combinaciones atípicas de múltiples variables;
- es más simple de operar y explicar que un modelo de deep learning para el volumen y naturaleza de este ejercicio.

### Dataset sintético

Se genera un dataset representativo de accesos a una tienda WordPress/WooCommerce.

El tráfico normal incluye navegación a:

- `/`
- `/shop`
- `/product/*`
- `/cart`
- `/checkout`
- `/my-account-2/`

Los escenarios anómalos utilizados para validar el modelo son:

1. fuerza bruta contra `/wp-login.php`;
2. escaneo y enumeración de rutas;
3. volumen excesivo de solicitudes;
4. sondeo de endpoints y archivos sensibles.

Las etiquetas del dataset se utilizan únicamente para evaluar el rendimiento. El modelo se entrena con las muestras normales.

### Variables utilizadas

La API agrega los registros por IP dentro del lote recibido y calcula:

- número total de solicitudes;
- solicitudes fallidas;
- respuestas `401/403`;
- respuestas `404`;
- errores `5xx`;
- número de rutas únicas;
- intentos contra `wp-login.php`;
- accesos a endpoints sensibles;
- accesos a rutas potencialmente sospechosas;
- número de solicitudes `POST`;
- tiempo de respuesta promedio y máximo;
- proporción de errores;
- proporción de accesos sensibles.

Este enfoque permite detectar comportamiento, no únicamente firmas estáticas.

### Guardia volumétrica

La detección principal se realiza con Isolation Forest. Como control complementario, se aplica una guardia determinística cuando una misma IP supera 100 solicitudes dentro del lote analizado.

La razón es técnica: los modelos basados en árboles pueden no extrapolar de forma óptima valores muy superiores al rango observado durante el entrenamiento. La guardia reduce este punto ciego para escenarios de flood o abuso automatizado sin sustituir al modelo de anomalías.

### Motor de decisión

La predicción del modelo, la guardia volumétrica y el indicador de confianza se transforman en una acción:

| Condición | Acción |
|---|---|
| Anomalía con confianza >= 0.80 | `bloquear` |
| Anomalía o confianza >= 0.60 | `alertar` |
| Sin anomalía relevante | `ignorar` |

En un entorno productivo, la acción `bloquear` debería integrarse con un WAF, reverse proxy o sistema de control de acceso y estar acompañada de mecanismos contra falsos positivos.

---

## 4. Ejecución local

### Opción A: requirements.txt

Requiere Python 3.11 o superior.

```bash
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Instalar dependencias:

```bash
pip install -r requirements.txt
```

El repositorio ya incluye un dataset y un modelo entrenado. Para regenerarlos:

```bash
python scripts/generate_dataset.py
python scripts/train_model.py
```

Iniciar la API:

```bash
uvicorn app.main:app --reload
```

La documentación interactiva queda disponible en:

```text
http://localhost:8000/docs
```

### Opción B: Docker

```bash
docker build -t ai-threat-detection .
docker run --rm -p 8000:8000 ai-threat-detection
```

---

## 5. Uso del endpoint

### Solicitud normal

```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "records": [
      {
        "timestamp": "2026-07-18T10:30:00Z",
        "ip": "203.0.113.10",
        "method": "GET",
        "path": "/shop",
        "status_code": 200,
        "response_time_ms": 110
      },
      {
        "timestamp": "2026-07-18T10:30:10Z",
        "ip": "203.0.113.10",
        "method": "GET",
        "path": "/product/shirt",
        "status_code": 200,
        "response_time_ms": 98
      }
    ]
  }'
```

Respuesta de ejemplo:

```json
{
  "threat_detected": false,
  "confidence": 0.4689,
  "action": "ignorar",
  "records_analyzed": 2,
  "entities_analyzed": 1,
  "results": [
    {
      "ip": "203.0.113.10",
      "threat_detected": false,
      "confidence": 0.4689,
      "action": "ignorar",
      "probable_behavior": "comportamiento esperado",
      "indicators": [
        "sin indicadores relevantes en el lote analizado"
      ]
    }
  ]
}
```

### Ejemplo de posible fuerza bruta

```bash
$records = 1..60 | ForEach-Object {
    @{
        timestamp = "2026-07-20T10:30:00Z"
        ip = "198.51.100.99"
        method = "POST"
        path = "/wp-login.php"
        status_code = 401
        response_time_ms = 120
    }
}

$body = @{
    records = $records
} | ConvertTo-Json -Depth 5

Invoke-RestMethod `
    -Uri "http://127.0.0.1:8000/analyze" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body
```

Para una detección robusta, el lote debería representar una ventana temporal corta, por ejemplo cinco minutos, con suficiente actividad para calcular las variables de comportamiento.

Respuesta obtenida al analizar un lote de 60 intentos fallidos:

```json
{
  "threat_detected": true,
  "confidence": 0.9961,
  "action": "bloquear",
  "records_analyzed": 60,
  "entities_analyzed": 1,
  "results": [
    {
      "ip": "198.51.100.99",
      "threat_detected": true,
      "confidence": 0.9961,
      "action": "bloquear",
      "probable_behavior": "posible fuerza bruta",
      "indicators": [
        "múltiples intentos fallidos contra wp-login.php",
        "tasa de error HTTP elevada",
        "cantidad elevada de solicitudes POST"
      ]
    }
  ]
}
```

---

## 6. Entrenamiento y evaluación

Regenerar dataset:

```bash
python scripts/generate_dataset.py
```

Entrenar y evaluar:

```bash
python scripts/train_model.py
```

Las métricas se guardan en:

```text
models/metrics.json
```

Las etiquetas de los escenarios sintéticos permiten medir precisión, recall y F1 después del entrenamiento, aunque no son utilizadas para ajustar directamente el modelo.

Resultados obtenidos en la evaluación sintética incluida:

| Métrica | Resultado |
|---|---:|
| Precision | 0.9174 |
| Recall | 1.0000 |
| F1 | 0.9569 |

La evaluación utiliza el 20% del tráfico normal reservado fuera del entrenamiento y los 100 escenarios sintéticos de ataque. Estas métricas validan el funcionamiento de la prueba de concepto, pero no deben interpretarse como rendimiento esperado en tráfico real.

---

## 7. Pruebas

```bash
pytest -q
```

Las pruebas incluidas validan:

- disponibilidad del servicio;
- aceptación de un lote normal;
- detección de un patrón de fuerza bruta.

---
