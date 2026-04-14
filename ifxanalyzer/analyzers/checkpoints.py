from collections import Counter
from analyzers.base import BaseAnalyzer


class CheckpointsAnalyzer(BaseAnalyzer):
    name          = "Checkpoints (onstat -g ckp)"
    description   = "Analiza triggers, tiempos y advertencias del physical log."
    output_file   = "salida_checkpoints.txt"
    file_patterns = ["onstat.g.ckp"]

    def analyze_to_file(self, files: dict, out):
        path = files.get("onstat.g.ckp")
        lines = self.read_file(path)
        for ctx, block in self.split_into_blocks(lines):
            self._bloque(block, ctx, out)

    def _bloque(self, lines, ctx, out):
        triggers, total_times = self._parse_ckp_table(lines)
        warning = self._extract_warning(lines)
        print("=" * 60, file=out)
        if ctx:
            print(ctx, file=out); print("-" * 60, file=out)
        if not total_times:
            print("No se encontraron filas de checkpoints en la salida (onstat -g ckp).", file=out)
            print("=" * 60, file=out); print(file=out); return

        print("1) Análisis de triggers de checkpoints", file=out)
        print("-------------------------------------", file=out)
        norm = [t.upper() for t in triggers]
        counts = Counter(triggers)
        if set(norm) == {"CKPTINTVL"}:
            print("Todos los checkpoints fueron disparados por CKPTINTVL.", file=out)
        else:
            print("Se encontraron triggers distintos a CKPTINTVL.", file=out)
            for trig, cnt in counts.items():
                print(f"  {trig}: {cnt} veces", file=out)
        print(file=out)

        print("2) Análisis de Total Time de checkpoints", file=out)
        print("---------------------------------------", file=out)
        n = len(total_times)
        print(f"Cantidad de checkpoints analizados : {n}", file=out)
        print(f"Suma de Total Time                 : {sum(total_times):.2f} segundos", file=out)
        print(f"Promedio de Total Time             : {sum(total_times)/n:.2f} segundos", file=out)
        print(f"Total Time mínimo observado        : {min(total_times):.2f} segundos", file=out)
        print(f"Total Time máximo observado        : {max(total_times):.2f} segundos", file=out)
        print(file=out)

        if warning:
            print("3) Advertencia sobre tamaño del Physical Log", file=out)
            print("-------------------------------------------", file=out)
            print(warning, file=out); print(file=out)

        print("=" * 60, file=out); print(file=out)

    def _parse_ckp_table(self, lines):
        triggers, total_times = [], []
        header_idx = next((i for i, l in enumerate(lines) if "Interval" in l and "Trigger" in l), None)
        if header_idx is None:
            return triggers, total_times
        for line in lines[header_idx + 1:]:
            s = line.strip()
            if not s or s.startswith("Max Plog"): break
            parts = s.split()
            if len(parts) >= 5 and parts[0].isdigit():
                try: triggers.append(parts[2]); total_times.append(float(parts[4]))
                except (ValueError, IndexError): pass
        return triggers, total_times

    def _extract_warning(self, lines):
        start = next((i for i, l in enumerate(lines) if l.strip().startswith("Based on the current workload")), None)
        if start is None: return None
        result = []
        for j in range(start, len(lines)):
            if j > start and not lines[j].strip(): break
            result.append(lines[j].rstrip("\n"))
        return "\n".join(result)
