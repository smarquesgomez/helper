from analyzers.base import BaseAnalyzer, Finding, Severity

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
