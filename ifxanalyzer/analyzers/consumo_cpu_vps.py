from analyzers.base import BaseAnalyzer, Finding, Severity

class CpuVpsAnalyzer(BaseAnalyzer):
    name = "CPU / VPs (onstat -g act/glo/rea)"
    description = "Analiza threads activos, sesiones, Virtual Processors y threads en espera."
    file_patterns = ["onstat.g.act", "onstat.g.glo", "onstat.g.rea"]

    def analyze(self, files: dict) -> list:
        act_path = files.get("onstat.g.act")
        glo_path = files.get("onstat.g.glo")
        rea_path = files.get("onstat.g.rea")
        if not (act_path and glo_path and rea_path):
            return [Finding(
                title="CPU / VPs — archivos faltantes",
                message="Se necesitan onstat.g.act, onstat.g.glo y onstat.g.rea.",
                severity=Severity.INFO,
            )]

        from collections import Counter
        act_lines = self.read_file(act_path)
        glo_lines = self.read_file(glo_path)
        rea_lines = self.read_file(rea_path)

        findings = []

        # Running threads
        in_table = False
        counts = Counter()
        for line in act_lines:
            s = line.strip()
            if s.startswith("Running threads:"):
                in_table = True; continue
            if in_table:
                if not s: break
                parts = s.split()
                if len(parts) >= 7 and parts[0].isdigit() and parts[4].lower() == "running":
                    counts[parts[-1]] += 1

        total_running = sum(counts.values())
        detalle = "\n".join(f"  {c}  {n}" for n, c in sorted(counts.items(), key=lambda x: -x[1]))
        findings.append(Finding(
            title="Threads running",
            message=f"Total de threads en estado running: {total_running}",
            severity=Severity.INFO,
            metric=str(total_running),
            detail=detalle or "Ningún thread running encontrado.",
        ))

        # Sessions / Threads globales
        sessions = threads = None
        for i, line in enumerate(glo_lines):
            if line.startswith("MT global info:"):
                j = i + 1
                while j < len(glo_lines) and not glo_lines[j].strip(): j += 1
                j += 1
                while j < len(glo_lines) and not glo_lines[j].strip(): j += 1
                if j < len(glo_lines):
                    data = glo_lines[j].split()
                    if len(data) >= 2 and data[0].isdigit():
                        sessions, threads = int(data[0]), int(data[1])
                break

        if sessions is not None:
            ratio = threads / sessions if sessions > 0 else 0
            findings.append(Finding(
                title="Sesiones / Threads globales",
                message=f"Sesiones: {sessions} | Threads: {threads} | Ratio: {ratio:.2f} threads/sesión",
                severity=Severity.INFO,
                metric=f"{sessions} sesiones",
            ))

        # VPs por clase
        vp_counts = Counter()
        in_vp = False
        for line in glo_lines:
            s = line.strip()
            if s.startswith("Individual virtual processors:"):
                in_vp = True; continue
            if in_vp:
                if not s or s.lower().startswith("tot"): break
                parts = s.split()
                if parts and parts[0].isdigit() and len(parts) >= 3:
                    vp_counts[parts[2]] += 1

        if vp_counts:
            detalle_vp = "\n".join(f"  Clase {cls}: {cnt} VP(s)"
                                    for cls, cnt in sorted(vp_counts.items(), key=lambda x: -x[1]))
            findings.append(Finding(
                title="Virtual Processors",
                message=f"Total VP classes: {len(vp_counts)}",
                severity=Severity.INFO,
                metric=f"{sum(vp_counts.values())} VPs",
                detail=detalle_vp,
            ))

        # Ready threads
        ready = 0
        in_rea = False
        for line in rea_lines:
            s = line.strip()
            if s.startswith("Ready threads:"): in_rea = True; continue
            if in_rea:
                if s.startswith("tid"): continue
                if not s: break
                if s.split()[0].isdigit(): ready += 1

        sev = Severity.WARNING if ready > 10 else Severity.OK
        findings.append(Finding(
            title="Threads en estado READY",
            message=f"Hay {ready} thread(s) en cola esperando un VP.",
            severity=sev,
            metric=str(ready),
        ))

        return findings
