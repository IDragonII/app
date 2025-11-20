# backend.py
from flask import Flask, request, jsonify
import pickle
import re
import traceback
import csv
from datetime import datetime
from pathlib import Path
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # permite llamadas fetch desde la extensión/desarrollo

# --- Define la función que tu pipeline necesita ---
def url_tokenizer(url):
    tokens = re.findall(r'[A-Za-z0-9]+', url)
    return tokens

# --- Carga del modelo ---
try:
    with open('phishing.pkl', 'rb') as f:
        modelo = pickle.load(f)
except Exception as e:
    print("Error cargando phishing.pkl:", e)
    raise

# --- Preparar archivo CSV para logs ---
LOG_CSV = Path("phish_logs.csv")
if not LOG_CSV.exists():
    with LOG_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "url", "raw_pred", "mapped_pred", "proba"])

def log_detection(url, raw_pred, mapped_pred, proba=None):
    ts = datetime.utcnow().isoformat() + "Z"
    with LOG_CSV.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([ts, url, str(raw_pred), str(mapped_pred), repr(proba)])
    print(f"[LOG] {ts} DETECTED PHISHING -> {url} (raw: {raw_pred}, mapped: {mapped_pred}, proba: {proba})")

# --- Endpoint de prueba ---
@app.route("/", methods=["GET"])
def home():
    return "Backend OK"

# --- Endpoint para predecir una sola URL vía JSON ---
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        url = data.get("url", "")
        if not url:
            return jsonify({"error": "No url provided"}), 400

        # El modelo espera una lista de muestras
        pred = modelo.predict([url])[0]

        # intentar obtener probabilidades si existe
        proba = None
        if hasattr(modelo, "predict_proba"):
            try:
                p = modelo.predict_proba([url])[0]
                # devolver como lista de floats
                proba = [float(x) for x in p]
            except Exception:
                proba = None

        # Normalizar nombre de clase a 'phishing' / 'legit' (ajusta según tu etiquetado)
        mapped = None
        try:
            classes = getattr(modelo, "classes_", None)
            # si las clases son strings como 'bad'/'good':
            if classes is not None and all(isinstance(c, str) for c in classes):
                mapped = str(pred)
                if mapped.lower() in ['bad', 'phishing', '1', 'true', 't', 'yes']:
                    mapped = 'phishing'
                else:
                    mapped = 'legit'
            else:
                # si pred es 0/1
                mapped = 'phishing' if int(pred) == 1 else 'legit'
        except Exception:
            mapped = 'phishing' if str(pred).lower() in ['1', 'bad', 'phishing'] else 'legit'

        # --- Aquí: guardar automáticamente cuando detecte phishing ---
        if str(mapped).lower() == 'phishing':
            try:
                log_detection(url, pred, mapped, proba)
            except Exception as e:
                print("Error al guardar log_detection:", e)

        return jsonify({
            "prediction": mapped,
            "raw_pred": str(pred),
            "proba": proba
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "internal error", "detail": str(e)}), 500

if __name__ == "__main__":
    # Ejecutar en localhost:5000
    app.run(host="127.0.0.1", port=5000, debug=False)
