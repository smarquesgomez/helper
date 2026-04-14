"""
app.py — Rutas Flask de la aplicación web.
"""

import os
import json
import tempfile
import shutil

from flask import Flask, request, jsonify, render_template, send_from_directory

from core.runner import run_on_folder, run_on_files, results_to_dict
from core.filtrar import filtrar

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB


# ── Rutas principales ──────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze/files", methods=["POST"])
def analyze_files():
    """
    Recibe archivos onstat subidos directamente.
    Form-data: files[] = lista de archivos
    """
    uploaded = request.files.getlist("files[]")
    if not uploaded:
        return jsonify({"error": "No se recibieron archivos."}), 400

    tmp_dir = tempfile.mkdtemp(prefix="ifx_")
    try:
        saved_paths = []
        for f in uploaded:
            dest = os.path.join(tmp_dir, f.filename)
            f.save(dest)
            saved_paths.append(dest)

        results = run_on_files(saved_paths)
        return jsonify({"results": results_to_dict(results)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.route("/api/patterns", methods=["GET"])
def get_patterns():
    """Devuelve los patrones de archivos que reconoce la app."""
    from analyzers.registry import get_required_patterns
    return jsonify({"patterns": get_required_patterns()})
