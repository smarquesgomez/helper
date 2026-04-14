"""
main.py — Punto de entrada.
Levanta Flask en background y abre el browser automáticamente.
Compatible con PyInstaller (--onefile).
"""

import sys
import os
import threading
import webbrowser
import time

# PyInstaller pone los archivos en sys._MEIPASS cuando es onefile
if getattr(sys, "frozen", False):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Agregamos BASE_DIR al path para que los imports funcionen desde el exe
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

PORT = 5000
HOST = "127.0.0.1"


def open_browser():
    time.sleep(1.2)
    webbrowser.open(f"http://{HOST}:{PORT}")


if __name__ == "__main__":
    from app import app

    # Cambiar al directorio base para que Flask encuentre templates/static
    os.chdir(BASE_DIR)

    print(f"[IFX Analyzer] Iniciando en http://{HOST}:{PORT} ...")
    print("[IFX Analyzer] Abriendo browser...")

    t = threading.Thread(target=open_browser, daemon=True)
    t.start()

    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
