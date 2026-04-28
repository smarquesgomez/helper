from collections import Counter
from analyzers.base import BaseAnalyzer


class LoggingAnalyzer(BaseAnalyzer):
    name          = "Logging (onstat -l)"
    description   = "Analiza physical log, logical log buffer y estado de los logical logs."
    order         = 7
    output_file   = "salida_onstat.l.txt"
    file_patterns = ["onstat.l"]

    def analyze_to_file(self, files: dict, out):
        path = files.get("onstat.l")
        lines = self.read_file(path)
        for ctx, block in self.split_into_blocks(lines):
            self._bloque(block, ctx, out)

    def _bloque(self, lines, ctx, out):
        phys = self._parse_physical(lines)
        logi = self._parse_logical(lines)
        lt   = self._parse_log_table(lines)

        print("=" * 60, file=out)
        if ctx:
            print(ctx, file=out); print("-" * 60, file=out)

        # Physical log buffer
        print("PHYSICAL LOG", file=out)
        print("------------", file=out)
        if phys["bufsize"] is not None and phys["pages_io"] is not None:
            ratio = (phys["pages_io"] / phys["bufsize"] * 100) if phys["bufsize"] > 0 else 0
            print(f"Buffer size (bufsize): {phys['bufsize']} páginas", file=out)
            print(f"pages/io             : {phys['pages_io']:.2f}", file=out)
            print(f"pages/io vs bufsize  : {ratio:.2f}% del tamaño del buffer", file=out)
            if ratio > 75:
                print("  ALERTA: pages/io supera el 75% del tamaño del buffer (buffer chico).", file=out)
            else:
                print("  OK: pages/io por debajo del 75% del tamaño del buffer.", file=out)
        else:
            print("No se pudieron leer bufsize/pages_io del Physical Logging.", file=out)
        print(file=out)

        if phys["pct_used"] is not None:
            print(f"physize : {phys['physize']} páginas", file=out)
            print(f"phyused : {phys['phyused']} páginas", file=out)
            print(f"%used   : {phys['pct_used']:.2f}%", file=out)
            if phys["pct_used"] >= 75:
                print("  ALERTA: %used del physical log >= 75% (riesgo de checkpoint bloqueante).", file=out)
            elif phys["pct_used"] >= 5:
                print("  ATENCIÓN: %used del physical log supera el 5%, pero < 75%.", file=out)
            else:
                print("  OK: %used del physical log muy por debajo del 75%.", file=out)
        print(file=out)

        # Logical log buffer
        print("LOGICAL LOG BUFFER", file=out)
        print("------------------", file=out)
        if logi["bufsize"] is not None and logi["pages_io"] is not None:
            ratio = (logi["pages_io"] / logi["bufsize"] * 100) if logi["bufsize"] > 0 else 0
            print(f"Buffer size (bufsize): {logi['bufsize']} páginas", file=out)
            print(f"pages/io             : {logi['pages_io']:.2f}", file=out)
            print(f"pages/io vs bufsize  : {ratio:.4f}% del tamaño del buffer", file=out)
            if ratio > 75:
                print("  ALERTA: pages/io del buffer de logical logs supera el 75%.", file=out)
            else:
                print("  OK: pages/io del buffer de logical logs muy por debajo del 75%.", file=out)
        else:
            print("No se pudieron leer bufsize/pages_io del Logical Logging.", file=out)
        print(file=out)

        # Logical logs tabla
        print("LOGICAL LOGS (detalle de logs)", file=out)
        print("------------------------------", file=out)
        if lt["total_logs"] is None and not lt["flag_counts"]:
            print("No se encontró la tabla de logical logs en la salida.", file=out)
        else:
            if lt["total_logs"] is not None:
                print(f"Total de logical logs: {lt['total_logs']}", file=out)
            if lt["active_logs"] is not None:
                print(f"Logical logs activos : {lt['active_logs']}", file=out)
            print(f"Cantidad de logs con flags 'U-B----' (backup): {lt['backup_count']}", file=out)

            for cur in lt["current_logs"]:
                print(f"Log actual (flags con 'C'): número {cur['number']}, flags {cur['flags']}, "
                      f"size {cur['size']} páginas, used {cur['used']} páginas ({cur['percent_used']}% usado)", file=out)
            if not lt["current_logs"]:
                print("No se identificó ningún log actual (sin flags con 'C').", file=out)

            print(file=out)
            print("Tipos de flags y cantidad de logs por tipo:", file=out)
            for flags, cnt in sorted(lt["flag_counts"].items(), key=lambda x: -x[1]):
                print(f"  {flags}: {cnt}", file=out)

            current_flag_set = {cl["flags"] for cl in lt["current_logs"]}
            other = [f for f in lt["flag_counts"] if f != "U-B----" and f not in current_flag_set]
            if other:
                print(file=out)
                print("ALERTA: Se encontraron flags distintos de 'U-B----' y del log actual:", file=out)
                for f in sorted(other):
                    print(f"  - {f} ({lt['flag_counts'][f]} log(s))", file=out)
            else:
                print(file=out)
                print("OK: además del log actual, todos los demás logs tienen flags 'U-B----'.", file=out)

            print(file=out)
            if lt["common_size"] is not None:
                print(f"Tamaño de logical log (size): {lt['common_size']} páginas (todos iguales).", file=out)
            elif lt["sizes"]:
                print("Se encontraron tamaños de logical logs distintos.", file=out)
                print(f"Tamaños detectados (páginas): {', '.join(str(s) for s in sorted(lt['sizes']))}", file=out)

        print("=" * 60, file=out); print(file=out)

    def _parse_physical(self, lines):
        r = {"bufsize": None, "pages_io": None, "physize": None, "phyused": None, "pct_used": None}
        n = len(lines)
        for i, line in enumerate(lines):
            if not line.strip().startswith("Physical Logging"): continue
            j = i + 1
            while j < n and not lines[j].strip().startswith("Buffer bufused"): j += 1
            if j < n:
                j += 1
                while j < n and not lines[j].strip(): j += 1
                if j < n:
                    d = lines[j].split()
                    if len(d) >= 6:
                        try: r["bufsize"] = int(d[2]); r["pages_io"] = float(d[5])
                        except ValueError: pass
            k = i + 1
            while k < n and not lines[k].strip().startswith("phybegin"): k += 1
            if k < n:
                k += 1
                while k < n and not lines[k].strip(): k += 1
                if k < n:
                    d = lines[k].split()
                    if len(d) >= 5:
                        try: r["physize"]=int(d[1]); r["phyused"]=int(d[3]); r["pct_used"]=float(d[4])
                        except ValueError: pass
            break
        return r

    def _parse_logical(self, lines):
        r = {"bufsize": None, "pages_io": None}
        n = len(lines)
        for i, line in enumerate(lines):
            if not line.strip().startswith("Logical Logging"): continue
            j = i + 1
            while j < n and not lines[j].strip().startswith("Buffer bufused"): j += 1
            if j < n:
                j += 1
                while j < n and not lines[j].strip(): j += 1
                if j < n:
                    d = lines[j].split()
                    if len(d) >= 8:
                        try: r["bufsize"] = int(d[2]); r["pages_io"] = float(d[7])
                        except ValueError: pass
            break
        return r

    def _parse_log_table(self, lines):
        fc = Counter(); backup = 0; current = []; sizes = set()
        active = total = None; in_table = False
        for line in lines:
            s = line.strip()
            if s.startswith("address") and "flags" in s and "begin" in s:
                in_table = True; continue
            if not in_table: continue
            if not s: continue
            if "active" in s and "total" in s:
                parts = s.replace(",","").split()
                nums = [p for p in parts if p.isdigit()]
                if len(nums) >= 2: active, total = int(nums[0]), int(nums[1])
                break
            parts = s.split()
            if len(parts) < 8: continue
            try: number = int(parts[1])
            except ValueError: continue
            flags = parts[2]
            try: size=int(parts[5]); used=int(parts[6]); pct=float(parts[7])
            except ValueError: size=used=pct=None
            fc[flags] += 1
            if flags == "U-B----": backup += 1
            if "C" in flags: current.append({"number":number,"flags":flags,"size":size,"used":used,"percent_used":pct})
            if size: sizes.add(size)
        return {"total_logs":total,"active_logs":active,"flag_counts":dict(fc),
                "backup_count":backup,"current_logs":current,"sizes":sizes,
                "common_size":next(iter(sizes)) if len(sizes)==1 else None}
