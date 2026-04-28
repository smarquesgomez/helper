from analyzers.base import BaseAnalyzer


class SharedMemoryAnalyzer(BaseAnalyzer):
    name          = "Shared Memory (onstat -g seg)"
    description   = "Analiza segmentos de clase V y disponibilidad de memoria compartida."
    order         = 2
    output_file   = "shared_memory_onstat.g.seg.txt"
    file_patterns = ["onstat.g.seg"]

    def analyze_to_file(self, files: dict, out):
        path = files.get("onstat.g.seg")
        lines = self.read_file(path)
        for ctx, block in self.split_into_blocks(lines):
            self._bloque(block, ctx, out)

    def _bloque(self, lines, ctx, out):
        v_segs = self._parse(lines)
        print("=" * 60, file=out)
        if ctx:
            print(ctx, file=out); print("-" * 60, file=out)

        if not v_segs:
            print("No se encontraron segmentos de clase V en la salida.", file=out)
            print("=" * 60, file=out); print(file=out); return

        total_v = len(v_segs)
        print(f"Cantidad de segmentos de clase V: {total_v}", file=out)
        print(file=out)

        if total_v == 1:
            used, free = v_segs[0]
            total = used + free
            pct_free = (free / total * 100) if total > 0 else 0
            print(f"Segmento V único:", file=out)
            print(f"  blkused = {used}", file=out)
            print(f"  blkfree = {free}", file=out)
            print(f"  Porcentaje de bloques libres: {pct_free:.2f}%", file=out)
            if free == 0:
                print("  ALERTA: blkfree es 0, no queda memoria libre en el segmento V.", file=out)
            elif pct_free < 5:
                print("  ATENCIÓN: blkfree es muy bajo, el segmento V está casi lleno.", file=out)
            else:
                print("  OK: aún hay memoria libre razonable en el segmento V.", file=out)
        else:
            print(f"Segmentos extra de clase V alocados (además del primero): {total_v - 1}", file=out)

        print("=" * 60, file=out); print(file=out)

    def _parse(self, lines):
        v_segs = []; in_summary = False; header_seen = False
        for line in lines:
            s = line.strip()
            if s.startswith("Segment Summary:"): in_summary = True; header_seen = False; continue
            if in_summary:
                if not header_seen:
                    if s.startswith("id"): header_seen = True
                    continue
                if not s or s.startswith("Total:"): break
                parts = s.split()
                if len(parts) >= 8 and parts[5].startswith("V"):
                    try: v_segs.append((int(parts[6]), int(parts[7])))
                    except ValueError: pass
        return v_segs
