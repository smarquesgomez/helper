from collections import Counter
from analyzers.base import BaseAnalyzer


class CpuVpsAnalyzer(BaseAnalyzer):
    name          = "CPU / VPs (onstat -g act/glo/rea)"
    description   = "Analiza threads activos, sesiones, Virtual Processors y threads en espera."
    output_file   = "salida_consumo_cpu_vps.txt"
    file_patterns = ["onstat.g.act", "onstat.g.glo", "onstat.g.rea"]

    def analyze_to_file(self, files: dict, out):
        act_lines = self.read_file(files.get("onstat.g.act"))
        glo_lines = self.read_file(files.get("onstat.g.glo"))
        rea_lines = self.read_file(files.get("onstat.g.rea"))

        act_counts          = self._parse_act(act_lines)
        sessions, threads   = self._parse_glo_mt(glo_lines)
        vp_counts           = self._parse_vp_classes(glo_lines)
        ready_threads       = self._parse_rea(rea_lines)

        print("ANÁLISIS DE CONSUMO CPU / THREADS VPS", file=out)
        print("=" * 60, file=out); print(file=out)

        # 1) Running threads
        print("1) onstat -g act  (threads activos 'running')", file=out)
        print("-" * 60, file=out)
        total_running = sum(act_counts.values())
        print(f"Total de threads running: {total_running}", file=out); print(file=out)
        for name, count in sorted(act_counts.items(), key=lambda x: -x[1]):
            print(f"{count}  {name}", file=out)
        if not act_counts:
            print("No se encontraron threads running en la salida.", file=out)
        print(file=out); print("=" * 60, file=out); print(file=out)

        # 2) MT global info
        print("2) onstat -g glo  (MT global info)", file=out)
        print("-" * 60, file=out)
        if sessions is not None and threads is not None:
            print(f"Sessions: {sessions}", file=out)
            print(f"Threads : {threads}", file=out)
            if sessions > 0:
                print(f"Threads por sesión: {threads/sessions:.2f}", file=out)
        else:
            print("No se pudieron leer sessions/threads de MT global info.", file=out)
        print(file=out)

        print("Detalle de VPs por clase (Individual virtual processors):", file=out)
        if vp_counts:
            for cls, cnt in sorted(vp_counts.items(), key=lambda x: -x[1]):
                print(f"Clase {cls:4s}: {cnt} VP(s)", file=out)
        else:
            print("No se pudo leer la sección 'Individual virtual processors'.", file=out)
        print(file=out); print("=" * 60, file=out); print(file=out)

        # 3) Ready threads
        print("3) onstat -g rea  (Ready threads)", file=out)
        print("-" * 60, file=out)
        print(f"Cantidad de threads en estado READY: {ready_threads}", file=out)
        print(file=out); print("=" * 60, file=out)

    def _parse_act(self, lines):
        in_table = False; counts = Counter()
        for line in lines:
            s = line.strip()
            if s.startswith("Running threads:"): in_table = True; continue
            if in_table:
                if not s: break
                parts = s.split()
                if len(parts) >= 7 and parts[0].isdigit() and parts[4].lower() == "running":
                    counts[parts[-1]] += 1
        return counts

    def _parse_glo_mt(self, lines):
        sessions = threads = None
        n = len(lines)
        for i, line in enumerate(lines):
            if not line.startswith("MT global info:"): continue
            j = i + 1
            while j < n and not lines[j].strip(): j += 1
            j += 1
            while j < n and not lines[j].strip(): j += 1
            if j < n:
                d = lines[j].split()
                if len(d) >= 2 and d[0].isdigit():
                    sessions, threads = int(d[0]), int(d[1])
            break
        return sessions, threads

    def _parse_vp_classes(self, lines):
        vp_counts = Counter(); in_vp = False
        for line in lines:
            s = line.strip()
            if s.startswith("Individual virtual processors:"): in_vp = True; continue
            if in_vp:
                if not s or s.lower().startswith("tot"): break
                if s.lower().startswith("vp"): continue
                parts = s.split()
                if parts and parts[0].isdigit() and len(parts) >= 3:
                    vp_counts[parts[2]] += 1
        return vp_counts

    def _parse_rea(self, lines):
        in_table = False; count = 0
        for line in lines:
            s = line.strip()
            if s.startswith("Ready threads:"): in_table = True; continue
            if in_table:
                if s.startswith("tid"): continue
                if not s: break
                if s.split()[0].isdigit(): count += 1
        return count
