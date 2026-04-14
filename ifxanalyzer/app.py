"""
app.py — Rutas Flask.
"""

import os
import shutil
import tempfile

from flask import Flask, request, jsonify, render_template, send_file, after_this_request

from core.runner import run_on_folder, run_on_files

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = None # Sin límite


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze/files", methods=["POST"])
def analyze_files():
    """
    Flujo 2: archivos sueltos subidos desde el browser.
    Devuelve un ZIP con los .txt de salida.
    """
    uploaded = request.files.getlist("files[]")
    output_name = request.form.get("output_name", "salidas_ifxcollect").strip() or "salidas_ifxcollect"

    if not uploaded:
        return jsonify({"error": "No se recibieron archivos."}), 400

    tmp_in  = tempfile.mkdtemp(prefix="ifx_in_")
    tmp_out = tempfile.mkdtemp(prefix="ifx_out_")

    try:
        saved = []
        for f in uploaded:
            dest = os.path.join(tmp_in, f.filename)
            f.save(dest)
            saved.append(dest)

        results = run_on_files(saved, tmp_out)

        # Empaquetar salidas en ZIP
        zip_path = _make_zip(tmp_out, output_name)

        @after_this_request
        def cleanup(response):
            shutil.rmtree(tmp_in, ignore_errors=True)
            shutil.rmtree(tmp_out, ignore_errors=True)
            try: os.remove(zip_path)
            except: pass
            return response

        ok_count  = sum(1 for r in results if r["ok"])
        err_count = sum(1 for r in results if not r["ok"])

        return send_file(
            zip_path,
            mimetype="application/zip",
            as_attachment=True,
            download_name=f"{output_name}.zip",
        )

    except Exception as e:
        shutil.rmtree(tmp_in, ignore_errors=True)
        shutil.rmtree(tmp_out, ignore_errors=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/patterns", methods=["GET"])
def get_patterns():
    from analyzers.registry import get_required_patterns
    return jsonify({"patterns": get_required_patterns()})


def _make_zip(folder: str, name: str) -> str:
    """Crea un ZIP del contenido de folder. Devuelve la ruta del ZIP."""
    zip_base = os.path.join(tempfile.gettempdir(), name)
    return shutil.make_archive(zip_base, "zip", folder)
