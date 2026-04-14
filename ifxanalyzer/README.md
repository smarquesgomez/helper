# IFX Analyzer v2.0

Herramienta web para analizar salidas de `onstat` generadas por **ifxcollect** (IBM Informix).

---

## Uso rápido

### Opción A — Ejecutar desde el código fuente (requiere Python 3.9+)

```bash
# 1. Instalar dependencias
pip install flask

# 2. Ejecutar
python main.py
```

Se abre automáticamente el browser en `http://localhost:5000`.

### Opción B — Generar el ejecutable (.exe / binario)

**Windows:**
```
build.bat
```

**Linux:**
```bash
chmod +x build.sh
./build.sh
```

El ejecutable queda en `dist/IFXAnalyzer` (o `dist/IFXAnalyzer.exe`).  
Los usuarios hacen **doble clic** y listo — no necesitan Python instalado.

---

## Cómo usar la app

1. Abrís la app (doble clic en el ejecutable o `python main.py`)
2. Se abre el browser automáticamente
3. Arrastrás los archivos `onstat.*` a la zona de carga (o los seleccionás con el botón)
4. Hacés clic en **Ejecutar análisis**
5. Ves los resultados con alertas coloreadas:
   - 🔴 **ALERTA** — problema crítico que requiere atención
   - 🟡 **ADVERTENCIA** — situación a monitorear
   - ✅ **OK** — dentro de los parámetros normales

---

## Agregar un nuevo analizador

Solo necesitás crear un archivo `.py` en la carpeta `analyzers/`. El sistema lo **detecta automáticamente**.

### Plantilla mínima

```python
# analyzers/mi_analizador.py

from analyzers.base import BaseAnalyzer, Finding, Severity

class MiAnalizador(BaseAnalyzer):
    name          = "Mi Analizador (onstat -x)"
    description   = "Descripción de qué analiza"
    file_patterns = ["onstat.g.xxx"]   # archivos que consume

    def analyze(self, files: dict) -> list:
        path = files.get("onstat.g.xxx")
        if not path:
            return []

        lines = self.read_file(path)
        findings = []

        # Tu lógica acá...
        valor = 42
        sev = Severity.ALERT if valor > 100 else Severity.OK

        findings.append(Finding(
            title   = "Nombre del check",
            message = f"El valor es {valor}.",
            severity= sev,
            metric  = str(valor),     # opcional: se muestra como badge
            detail  = "Texto extra\nque el usuario puede expandir",  # opcional
        ))

        return findings
```

### Severidades disponibles

| Severidad | Color | Cuándo usar |
|-----------|-------|-------------|
| `Severity.ALERT`   | 🔴 Rojo   | Problema crítico que necesita acción inmediata |
| `Severity.WARNING` | 🟡 Amarillo | Situación a monitorear, no es crítica todavía |
| `Severity.OK`      | ✅ Verde  | Dentro de los parámetros normales |
| `Severity.INFO`    | ℹ️ Azul   | Información sin juicio de valor |

### Métodos helper disponibles en BaseAnalyzer

```python
# Leer un archivo en lista de líneas
lines = self.read_file(path)

# Separar el archivo en bloques por "File Iteration ..."
blocks = self.split_into_blocks(lines)
for contexto, lineas_del_bloque in blocks:
    # contexto = "File Iteration 1 Time: ..."
    # lineas_del_bloque = lista de strings
    pass
```

---

## Estructura del proyecto

```
ifxanalyzer/
├── main.py                  ← punto de entrada (levanta Flask + abre browser)
├── app.py                   ← rutas Flask
├── requirements.txt
├── build.bat                ← genera .exe en Windows
├── build.sh                 ← genera binario en Linux
│
├── core/
│   ├── runner.py            ← orquestador: busca archivos y ejecuta analizadores
│   └── filtrar.py           ← filtra archivos relevantes de una carpeta ifxcollect
│
├── analyzers/               ← ¡Agregá tus analizadores acá!
│   ├── base.py              ← BaseAnalyzer, Finding, Severity, AnalyzerResult
│   ├── registry.py          ← auto-descubre los analizadores
│   ├── checkpoints.py       ← onstat -g ckp
│   ├── onstat_k.py          ← onstat -k
│   ├── onstat_l.py          ← onstat -l
│   └── others.py            ← onstat -g ntd, onstat -g seg, onstat -p, onstat -g act/glo/rea
│
├── templates/
│   └── index.html           ← UI web
└── static/
    ├── css/style.css
    └── js/app.js
```
