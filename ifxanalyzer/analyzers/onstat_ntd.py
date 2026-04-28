from analyzers.base import BaseAnalyzer


class NtdAnalyzer(BaseAnalyzer):
    name          = "Red / Clientes (onstat -g ntd)"
    description   = "Analiza conexiones de red y porcentaje de rejected por cliente."
    order         = 4
    output_file   = "ntd_onstat.g.ntd.txt"
    file_patterns = ["onstat.g.ntd"]

    def analyze_to_file(self, files: dict, out):
        path = files.get("onstat.g.ntd")
        lines = self.read_file(path)
        for ctx, block in self.split_into_blocks(lines):
            self._bloque(block, ctx, out)

    def _bloque(self, lines, ctx, out):
        clients = self._parse(lines)
        print("=" * 60, file=out)
        if ctx:
            print(ctx, file=out); print("-" * 60, file=out)
        print("ANÁLISIS onstat -g ntd (red / clientes)", file=out)
        print("---------------------------------------", file=out)

        if not clients:
            print("No se encontró la tabla de 'Client Type' en la salida.", file=out)
            print("=" * 60, file=out); print(file=out); return

        print("Resumen por cliente:", file=out)
        for c in clients:
            pct = c["pct_rejected"]
            if pct is not None:
                print(f"  {c['client_type']:12s} Accepted={c['accepted']:10d}, Rejected={c['rejected']:8d}, "
                      f"Rejected/Accepted={pct:6.3f}%", file=out)
            else:
                print(f"  {c['client_type']:12s} Accepted={c['accepted']:10d}, Rejected={c['rejected']:8d}, "
                      f"Rejected/Accepted= N/A (accepted=0)", file=out)
        print(file=out)

        print("Clientes con porcentaje de 'Rejected' > 1% de 'Accepted':", file=out)
        print("--------------------------------------------------------", file=out)
        found = False
        for c in clients:
            pct = c["pct_rejected"]
            if pct is not None and pct > 1.0:
                found = True
                print("ALERTA:", file=out)
                print(f"  Client Type       : {c['client_type']}", file=out)
                print(f"  Accepted          : {c['accepted']}", file=out)
                print(f"  Rejected          : {c['rejected']}", file=out)
                print(f"  Rejected/Accepted : {pct:.3f}% (> 1%)", file=out)
                print(file=out)
        if not found:
            print("  OK: en ningún Client Type los rejected superan el 1% de los accepted.", file=out)

        print("=" * 60, file=out); print(file=out)

    def _parse(self, lines):
        in_table = False; clients = []
        for line in lines:
            s = line.strip()
            if s.startswith("Client Type"): in_table = True; continue
            if in_table:
                if s.startswith("Totals"): break
                if not s or len(s.split()) < 6: continue
                parts = s.split()
                try: accepted=int(parts[2]); rejected=int(parts[3])
                except ValueError: continue
                pct = (rejected*100.0/accepted) if accepted > 0 else None
                clients.append({"client_type":parts[0],"accepted":accepted,"rejected":rejected,"pct_rejected":pct})
        return clients
