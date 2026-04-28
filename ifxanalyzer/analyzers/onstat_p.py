from analyzers.base import BaseAnalyzer


class OnstatPAnalyzer(BaseAnalyzer):
    name          = "Profile (onstat -p)"
    description   = "Analiza cache, commits/rollbacks, overflows, CPU, RA y deadlocks."
    order         = 5
    output_file   = "salida_onstat.p.txt"
    file_patterns = ["onstat.p"]

    def analyze_to_file(self, files: dict, out):
        path = files.get("onstat.p")
        lines = self.read_file(path)
        for ctx, block in self.split_into_blocks(lines):
            self._bloque(block, ctx, out)

    def _bloque(self, lines, ctx, out):
        d = self._parse(lines)
        print("=" * 60, file=out)
        if ctx:
            print(ctx, file=out); print("-" * 60, file=out)

        # Cache
        if d["read_cached"] is not None and d["write_cached"] is not None:
            print(f"Cache de lectura:   {d['read_cached']:.2f}%", file=out)
            if d["read_cached"] < 80:
                print("  ALERTA: %cached de lectura menor a 80%.", file=out)
            print(f"Cache de escritura: {d['write_cached']:.2f}%", file=out)
            if d["write_cached"] < 80:
                print("  ALERTA: %cached de escritura menor a 80%.", file=out)
        else:
            print("No se pudieron leer los porcentajes de cache.", file=out)
        print(file=out)

        # Commits/Rollbacks
        if d["commits"] is not None:
            print(f"Commits: {d['commits']}, Rollbacks: {d['rollbacks']}", file=out)
            if d["commits"] == 0:
                print("  No hay commits, no se puede calcular la relación commit/rollback.", file=out)
            else:
                ratio = d["rollbacks"] / d["commits"] * 100
                print(f"  Rollbacks/commits: {ratio:.2f}%", file=out)
                if ratio <= 3:
                    print("  OK: los rollbacks son <= 3% de los commits.", file=out)
                else:
                    print("  ALERTA: los rollbacks superan el 3% de los commits (overhead).", file=out)
        else:
            print("No se pudieron leer commits/rollbacks.", file=out)
        print(file=out)

        # Overflows
        if d["ovlock"] is not None:
            print("OVERFLOWS", file=out)
            print(f"  ovlock      : {d['ovlock']}", file=out)
            print(f"  ovuserthread: {d['ovuserthread']}", file=out)
            print(f"  ovbuff      : {d['ovbuff']}", file=out)
            if d["ovlock"] == 0 and d["ovuserthread"] == 0 and d["ovbuff"] == 0:
                print("  OK: no se registran overflows.", file=out)
            else:
                print("  ATENCIÓN: se registran overflows, revisar dimensionamiento.", file=out)
        else:
            print("No se pudieron leer los contadores de overflows.", file=out)
        print(file=out)

        # CPU
        if d["usercpu"] is not None:
            total_cpu = d["usercpu"] + d["syscpu"]
            user_pct = (d["usercpu"] / total_cpu * 100) if total_cpu > 0 else 0
            sys_pct  = (d["syscpu"]  / total_cpu * 100) if total_cpu > 0 else 0
            print(f"usercpu: {d['usercpu']:.2f} ({user_pct:.2f}%)", file=out)
            print(f"syscpu : {d['syscpu']:.2f} ({sys_pct:.2f}%)", file=out)
            if d["syscpu"] > 0.25 * d["usercpu"]:
                print("  ALERTA: syscpu supera el 25% de usercpu.", file=out)
            else:
                print("  OK: syscpu está dentro del 25% de usercpu.", file=out)
        else:
            print("No se pudieron leer usercpu/syscpu.", file=out)
        print(file=out)

        # RA
        if d["ixdaRA"] is not None:
            suma = d["ixdaRA"] + d["idxRA"] + d["daRA"]
            ratio = (d["rpgs"] * 100.0 / suma) if suma > 0 else 0
            print(f"ixda-RA + idx-RA + da-RA = {suma} páginas", file=out)
            print(f"RA-pgsused                = {d['rpgs']} páginas", file=out)
            print(f"Relación RA-pgsused / (ixda-RA + idx-RA + da-RA) = {ratio:.2f}%", file=out)
            if ratio < 70:
                print("  ALERTA: RA-pgsused representa menos del 70% del total de RA.", file=out)
            elif ratio <= 80:
                print("  ATENCIÓN: la relación está entre 70% y 80%.", file=out)
            else:
                print("  OK: la relación RA-pgsused está por encima del 80%.", file=out)
        else:
            print("No se pudieron leer los valores de RA.", file=out)
        print(file=out)

        # Deadlocks
        if d["deadlks"] is not None:
            print(f"deadlks = {d['deadlks']}, dltouts = {d['dltouts']}", file=out)
            if d["deadlks"] > 0 or d["dltouts"] > 0:
                print("  ALERTA: hay deadlocks o timeouts de bloqueo.", file=out)
            else:
                print("  OK: no se registran deadlocks ni timeouts de bloqueo.", file=out)
        else:
            print("No se pudieron leer deadlks/dltouts.", file=out)

        print("=" * 60, file=out); print(file=out)

    def _parse(self, lines):
        d = {k: None for k in ["read_cached","write_cached","commits","rollbacks",
                                 "ovlock","ovuserthread","ovbuff","usercpu","syscpu",
                                 "deadlks","dltouts","ixdaRA","idxRA","daRA","rpgs"]}
        n = len(lines)
        i = 0
        while i < n:
            parts = lines[i].split()
            if not parts: i += 1; continue
            def nd():
                j = i + 1
                while j < n and not lines[j].strip(): j += 1
                return lines[j].split() if j < n else []
            if parts[0] == "dskreads":
                v = nd()
                if len(v) >= 8:
                    try: d["read_cached"]=float(v[3]); d["write_cached"]=float(v[7])
                    except ValueError: pass
            elif parts[0] == "isamtot":
                v = nd()
                if len(v) >= 2:
                    try: d["commits"]=int(v[-2]); d["rollbacks"]=int(v[-1])
                    except ValueError: pass
            elif parts[0] == "ovlock":
                v = nd()
                if len(v) >= 5:
                    try: d["ovlock"]=int(v[0]); d["ovuserthread"]=int(v[1]); d["ovbuff"]=int(v[2]); d["usercpu"]=float(v[3]); d["syscpu"]=float(v[4])
                    except ValueError: pass
            elif parts[0] == "bufwaits":
                v = nd()
                if len(v) >= 5:
                    try: d["deadlks"]=int(v[3]); d["dltouts"]=int(v[4])
                    except ValueError: pass
            elif parts[0] == "ixda-RA":
                v = nd()
                if len(v) >= 5:
                    try: d["ixdaRA"]=int(v[0]); d["idxRA"]=int(v[1]); d["daRA"]=int(v[2]); d["rpgs"]=int(v[4])
                    except ValueError: pass
            i += 1
        return d
