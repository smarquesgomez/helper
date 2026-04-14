from analyzers.base import BaseAnalyzer, Finding, Severity


class NtdAnalyzer(BaseAnalyzer):
    name = "Red / Clientes (onstat -g ntd)"
    description = "Analiza conexiones de red y porcentaje de rejected por tipo de cliente."
    file_patterns = ["onstat.g.ntd"]

    def analyze(self, files: dict) -> list:
        path = files.get("onstat.g.ntd")
        if not path:
            return []
        lines = self.read_file(path)
        blocks = self.split_into_blocks(lines)
        findings = []
        for ctx, block in blocks:
            findings.extend(self._analyze_block(block, ctx))
        return findings

    def _analyze_block(self, lines, ctx):
        findings = []
        clients = self._parse(lines)
        prefix = f"[{ctx}] " if ctx else ""

        if not clients:
            findings.append(Finding(
                title=f"{prefix}Sin datos de clientes",
                message="No se encontró la tabla de Client Type.",
                severity=Severity.INFO,
            ))
            return findings

        alerts = [c for c in clients if c["pct_rejected"] and c["pct_rejected"] > 1.0]
        sev = Severity.ALERT if alerts else Severity.OK
        resumen = "\n".join(
            f"  {c['client_type']:12s} accepted={c['accepted']:>10,}  rejected={c['rejected']:>8,}"
            + (f"  ({c['pct_rejected']:.3f}%)" if c["pct_rejected"] else "")
            for c in clients
        )
        msg = (f"{len(alerts)} cliente(s) superan 1% de rejected." if alerts
               else "Ningún cliente supera el 1% de rejected.")
        findings.append(Finding(
            title=f"{prefix}Conexiones de red",
            message=msg,
            severity=sev,
            detail=resumen,
        ))
        return findings

    def _parse(self, lines):
        in_table = False
        clients = []
        for line in lines:
            s = line.strip()
            if s.startswith("Client Type"):
                in_table = True
                continue
            if in_table:
                if s.startswith("Totals"):
                    break
                if not s or len(s.split()) < 6:
                    continue
                parts = s.split()
                try:
                    accepted = int(parts[2])
                    rejected = int(parts[3])
                except ValueError:
                    continue
                pct = (rejected * 100.0 / accepted) if accepted > 0 else None
                clients.append({"client_type": parts[0], "accepted": accepted,
                                 "rejected": rejected, "pct_rejected": pct})
        return clients


class SharedMemoryAnalyzer(BaseAnalyzer):
    name = "Shared Memory (onstat -g seg)"
    description = "Analiza segmentos de clase V y disponibilidad de memoria compartida."
    file_patterns = ["onstat.g.seg"]

    def analyze(self, files: dict) -> list:
        path = files.get("onstat.g.seg")
        if not path:
            return []
        lines = self.read_file(path)
        blocks = self.split_into_blocks(lines)
        findings = []
        for ctx, block in blocks:
            findings.extend(self._analyze_block(block, ctx))
        return findings

    def _analyze_block(self, lines, ctx):
        findings = []
        v_segs = self._parse(lines)
        prefix = f"[{ctx}] " if ctx else ""

        if not v_segs:
            findings.append(Finding(
                title=f"{prefix}Sin segmentos V",
                message="No se encontraron segmentos de clase V.",
                severity=Severity.INFO,
            ))
            return findings

        total_v = len(v_segs)
        if total_v == 1:
            used, free = v_segs[0]
            total = used + free
            pct_free = (free / total * 100) if total > 0 else 0
            sev = Severity.ALERT if free == 0 else (Severity.WARNING if pct_free < 5 else Severity.OK)
            findings.append(Finding(
                title=f"{prefix}Shared memory",
                message=f"Segmento V: {pct_free:.1f}% libre ({free} bloques libres de {total}).",
                severity=sev,
                metric=f"{pct_free:.1f}% libre",
                detail=f"blkused: {used}\nblkfree: {free}\n% libre: {pct_free:.2f}%",
            ))
        else:
            findings.append(Finding(
                title=f"{prefix}Segmentos extra de memoria",
                message=f"Hay {total_v - 1} segmento(s) V adicional(es) alocados.",
                severity=Severity.WARNING,
                metric=f"{total_v} segmentos",
            ))
        return findings

    def _parse(self, lines):
        v_segs = []
        in_summary = False
        header_seen = False
        for line in lines:
            s = line.strip()
            if s.startswith("Segment Summary:"):
                in_summary = True
                header_seen = False
                continue
            if in_summary:
                if not header_seen:
                    if s.startswith("id"):
                        header_seen = True
                    continue
                if not s or s.startswith("Total:"):
                    break
                parts = s.split()
                if len(parts) < 8:
                    continue
                seg_class = parts[5]
                if seg_class.startswith("V"):
                    try:
                        v_segs.append((int(parts[6]), int(parts[7])))
                    except ValueError:
                        pass
        return v_segs


class OnstatPAnalyzer(BaseAnalyzer):
    name = "Profile (onstat -p)"
    description = "Analiza cache, commits/rollbacks, overflows, CPU, read-ahead y deadlocks."
    file_patterns = ["onstat.p"]

    def analyze(self, files: dict) -> list:
        path = files.get("onstat.p")
        if not path:
            return []
        lines = self.read_file(path)
        blocks = self.split_into_blocks(lines)
        findings = []
        for ctx, block in blocks:
            findings.extend(self._analyze_block(block, ctx))
        return findings

    def _analyze_block(self, lines, ctx):
        findings = []
        d = self._parse(lines)
        prefix = f"[{ctx}] " if ctx else ""

        # Cache
        if d["read_cached"] is not None:
            sev = Severity.ALERT if d["read_cached"] < 80 else Severity.OK
            findings.append(Finding(
                title=f"{prefix}Cache de lectura",
                message=f"{d['read_cached']:.2f}% de lecturas servidas desde caché.",
                severity=sev,
                metric=f"{d['read_cached']:.1f}%",
            ))
        if d["write_cached"] is not None:
            sev = Severity.ALERT if d["write_cached"] < 80 else Severity.OK
            findings.append(Finding(
                title=f"{prefix}Cache de escritura",
                message=f"{d['write_cached']:.2f}% de escrituras servidas desde caché.",
                severity=sev,
                metric=f"{d['write_cached']:.1f}%",
            ))

        # Commits/Rollbacks
        if d["commits"] is not None:
            if d["commits"] > 0:
                ratio = d["rollbacks"] / d["commits"] * 100
                sev = Severity.ALERT if ratio > 3 else Severity.OK
                findings.append(Finding(
                    title=f"{prefix}Commits / Rollbacks",
                    message=f"Rollbacks: {ratio:.2f}% de commits. ({d['commits']:,} commits, {d['rollbacks']:,} rollbacks)",
                    severity=sev,
                    metric=f"{ratio:.1f}% RB",
                ))

        # Overflows
        if d["ovlock"] is not None:
            any_ov = d["ovlock"] > 0 or d["ovuserthread"] > 0 or d["ovbuff"] > 0
            sev = Severity.ALERT if any_ov else Severity.OK
            msg = ("Se registran overflows — revisar dimensionamiento." if any_ov
                   else "No se registran overflows.")
            findings.append(Finding(
                title=f"{prefix}Overflows",
                message=msg,
                severity=sev,
                detail=f"ovlock: {d['ovlock']}\novuserthread: {d['ovuserthread']}\novbuff: {d['ovbuff']}",
            ))

        # CPU
        if d["usercpu"] is not None:
            total_cpu = d["usercpu"] + d["syscpu"]
            sys_pct = (d["syscpu"] / total_cpu * 100) if total_cpu > 0 else 0
            sev = Severity.ALERT if d["syscpu"] > 0.25 * d["usercpu"] else Severity.OK
            findings.append(Finding(
                title=f"{prefix}CPU",
                message=f"usercpu: {d['usercpu']:.2f} | syscpu: {d['syscpu']:.2f} ({sys_pct:.1f}% del total)",
                severity=sev,
                metric=f"sys {sys_pct:.1f}%",
            ))

        # Deadlocks
        if d["deadlks"] is not None:
            sev = Severity.ALERT if (d["deadlks"] > 0 or d["dltouts"] > 0) else Severity.OK
            findings.append(Finding(
                title=f"{prefix}Deadlocks / Timeouts",
                message=f"deadlks: {d['deadlks']} | dltouts: {d['dltouts']}",
                severity=sev,
                metric=f"{d['deadlks']} DL",
            ))

        # RA
        if d["ixdaRA"] is not None:
            suma = d["ixdaRA"] + d["idxRA"] + d["daRA"]
            ratio = (d["rpgs"] * 100.0 / suma) if suma > 0 else 0
            sev = Severity.ALERT if ratio < 70 else (Severity.WARNING if ratio < 80 else Severity.OK)
            findings.append(Finding(
                title=f"{prefix}Read Ahead (RA)",
                message=f"RA-pgsused / total RA = {ratio:.2f}%",
                severity=sev,
                metric=f"{ratio:.1f}% RA",
            ))

        return findings

    def _parse(self, lines):
        d = {k: None for k in ["read_cached","write_cached","commits","rollbacks",
                                 "ovlock","ovuserthread","ovbuff","usercpu","syscpu",
                                 "deadlks","dltouts","ixdaRA","idxRA","daRA","rpgs"]}
        n = len(lines)
        i = 0
        while i < n:
            parts = lines[i].split()
            if not parts:
                i += 1; continue
            def next_data():
                j = i + 1
                while j < n and not lines[j].strip():
                    j += 1
                return lines[j].split() if j < n else []

            if parts[0] == "dskreads":
                nd = next_data()
                if len(nd) >= 8:
                    try: d["read_cached"] = float(nd[3]); d["write_cached"] = float(nd[7])
                    except ValueError: pass
            elif parts[0] == "isamtot":
                nd = next_data()
                if len(nd) >= 2:
                    try: d["commits"] = int(nd[-2]); d["rollbacks"] = int(nd[-1])
                    except ValueError: pass
            elif parts[0] == "ovlock":
                nd = next_data()
                if len(nd) >= 5:
                    try:
                        d["ovlock"] = int(nd[0]); d["ovuserthread"] = int(nd[1])
                        d["ovbuff"] = int(nd[2]); d["usercpu"] = float(nd[3]); d["syscpu"] = float(nd[4])
                    except ValueError: pass
            elif parts[0] == "bufwaits":
                nd = next_data()
                if len(nd) >= 5:
                    try: d["deadlks"] = int(nd[3]); d["dltouts"] = int(nd[4])
                    except ValueError: pass
            elif parts[0] == "ixda-RA":
                nd = next_data()
                if len(nd) >= 5:
                    try:
                        d["ixdaRA"] = int(nd[0]); d["idxRA"] = int(nd[1])
                        d["daRA"] = int(nd[2]); d["rpgs"] = int(nd[4])
                    except ValueError: pass
            i += 1
        return d


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
