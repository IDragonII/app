from flask import Flask, request, render_template
import pickle
import re
import os

# -------------------------
# Definir tokenizador usado en el pipeline
# -------------------------
def url_tokenizer(url):
    tokens = re.findall(r'[A-Za-z0-9]+', url)
    return tokens

# -------------------------
# Cargar modelo
# -------------------------
with open('phishing.pkl', 'rb') as f:
    modelo = pickle.load(f)

# -------------------------
# Crear la app Flask
# -------------------------
app = Flask(__name__)

# Ruta principal (HTML)
@app.route("/", methods=["GET", "POST"])
def index():
    resultado = None
    urls_input = ""
    if request.method == "POST":
        urls_input = request.form.get("urls", "")
        urls = [u.strip() for u in urls_input.split("\n") if u.strip()]
        if urls:
            pred = modelo.predict(urls)
            # Mapear a etiquetas legibles
            resultado = ["phishing" if p == 'bad' or p == 1 else "legítima" for p in pred]
            resultado = list(zip(urls, resultado))
    return render_template("index.html", resultado=resultado, urls_input=urls_input)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

