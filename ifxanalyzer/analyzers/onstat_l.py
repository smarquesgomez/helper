from collections import Counter
from analyzers.base import BaseAnalyzer, Finding, Severity


class LoggingAnalyzer(BaseAnalyzer):
    name = "Logging (onstat -l)"
    description = "Analiza physical log, logical log buffer y estado de los logical logs."
    file_patterns = ["onstat.l"]

    def analyze(self, files: dict) -> list:
        path = files.get("onstat.l")
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
        phys = self._parse_physical_logging(lines)
        logi = self._parse_logical_logging(lines)
        log_table = self._parse_logical_log_table(lines)
        prefix = f"[{ctx}] " if ctx else ""

        # Physical log buffer
        if phys["bufsize"] and phys["pages_io"] is not None:
            ratio = (phys["pages_io"] / phys["bufsize"] * 100) if phys["bufsize"] > 0 else 0
            sev = Severity.ALERT if ratio > 75 else Severity.OK
            findings.append(Finding(
                title=f"{prefix}Physical log buffer",
                message=f"pages/io es {ratio:.1f}% del tamaño del buffer (bufsize={phys['bufsize']}).",
                severity=sev,
                metric=f"{ratio:.1f}%",
                detail=f"bufsize: {phys['bufsize']} páginas\npages/io: {phys['pages_io']:.2f}",
            ))

        # Physical log uso
        if phys["pct_used"] is not None:
            sev = Severity.ALERT if phys["pct_used"] >= 75 else (
                  Severity.WARNING if phys["pct_used"] >= 5 else Severity.OK)
            findings.append(Finding(
                title=f"{prefix}Physical log uso",
                message=f"El physical log está usado al {phys['pct_used']:.1f}%.",
                severity=sev,
                metric=f"{phys['pct_used']:.1f}%",
                detail=f"physize: {phys['physize']}\nphyused: {phys['phyused']}\n%used: {phys['pct_used']:.2f}%",
            ))

        # Logical log buffer
        if logi["bufsize"] and logi["pages_io"] is not None:
            ratio = (logi["pages_io"] / logi["bufsize"] * 100) if logi["bufsize"] > 0 else 0
            sev = Severity.ALERT if ratio > 75 else Severity.OK
            findings.append(Finding(
                title=f"{prefix}Logical log buffer",
                message=f"pages/io es {ratio:.4f}% del buffer lógico.",
                severity=sev,
                metric=f"{ratio:.2f}%",
            ))

        # Logical logs detalle
        lt = log_table
        if lt["total_logs"]:
            current_logs = lt["current_logs"]
            cur_info = ""
            if current_logs:
                cur = current_logs[0]
                cur_info = f"Log actual #{cur['number']} — {cur['percent_used']}% usado"

            other_flags = [
                f for f in lt["flag_counts"]
                if f != "U-B----" and f not in {cl["flags"] for cl in current_logs}
            ]
            sev = Severity.ALERT if other_flags else Severity.OK
            detalle = "Flags encontrados:\n" + "\n".join(
                f"  {f}: {c}" for f, c in sorted(lt["flag_counts"].items(), key=lambda x: -x[1])
            )
            findings.append(Finding(
                title=f"{prefix}Logical logs",
                message=f"Total: {lt['total_logs']} logs. {cur_info}",
                severity=sev,
                metric=f"{lt['total_logs']} logs",
                detail=detalle,
            ))

        return findings

    def _parse_physical_logging(self, lines):
        result = {"bufsize": None, "pages_io": None, "physize": None, "phyused": None, "pct_used": None}
        n = len(lines)
        for i, line in enumerate(lines):
            if line.strip().startswith("Physical Logging"):
                j = i + 1
                while j < n and not lines[j].strip().startswith("Buffer bufused"):
                    j += 1
                if j < n:
                    j += 1
                    while j < n and not lines[j].strip():
                        j += 1
                    if j < n:
                        data = lines[j].split()
                        if len(data) >= 6:
                            try:
                                result["bufsize"] = int(data[2])
                                result["pages_io"] = float(data[5])
                            except ValueError:
                                pass
                k = i + 1
                while k < n and not lines[k].strip().startswith("phybegin"):
                    k += 1
                if k < n:
                    k += 1
                    while k < n and not lines[k].strip():
                        k += 1
                    if k < n:
                        data = lines[k].split()
                        if len(data) >= 5:
                            try:
                                result["physize"] = int(data[1])
                                result["phyused"] = int(data[3])
                                result["pct_used"] = float(data[4])
                            except ValueError:
                                pass
                break
        return result

    def _parse_logical_logging(self, lines):
        result = {"bufsize": None, "pages_io": None}
        n = len(lines)
        for i, line in enumerate(lines):
            if line.strip().startswith("Logical Logging"):
                j = i + 1
                while j < n and not lines[j].strip().startswith("Buffer bufused"):
                    j += 1
                if j < n:
                    j += 1
                    while j < n and not lines[j].strip():
                        j += 1
                    if j < n:
                        data = lines[j].split()
                        if len(data) >= 8:
                            try:
                                result["bufsize"] = int(data[2])
                                result["pages_io"] = float(data[7])
                            except ValueError:
                                pass
                break
        return result

    def _parse_logical_log_table(self, lines):
        flag_counts = Counter()
        backup_count = 0
        current_logs = []
        sizes = set()
        active_logs = total_logs = None
        in_table = False

        for i, line in enumerate(lines):
            s = line.strip()
            if s.startswith("address") and "flags" in s and "begin" in s:
                in_table = True
                continue
            if in_table:
                if not s:
                    continue
                if "active" in s and "total" in s:
                    parts = s.replace(",", "").split()
                    nums = [p for p in parts if p.isdigit()]
                    if len(nums) >= 2:
                        active_logs, total_logs = int(nums[0]), int(nums[1])
                    break
                parts = s.split()
                if len(parts) < 8:
                    continue
                try:
                    number = int(parts[1])
                except ValueError:
                    continue
                flags = parts[2]
                try:
                    size = int(parts[5])
                    used = int(parts[6])
                    pct = float(parts[7])
                except ValueError:
                    size = used = pct = None
                flag_counts[flags] += 1
                if flags == "U-B----":
                    backup_count += 1
                if "C" in flags:
                    current_logs.append({"number": number, "flags": flags,
                                         "size": size, "used": used, "percent_used": pct})
                if size:
                    sizes.add(size)

        return {
            "total_logs": total_logs, "active_logs": active_logs,
            "flag_counts": dict(flag_counts), "backup_count": backup_count,
            "current_logs": current_logs, "sizes": sizes,
            "common_size": next(iter(sizes)) if len(sizes) == 1 else None,
        }
