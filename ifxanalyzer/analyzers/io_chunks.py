import re
from analyzers.base import BaseAnalyzer


class IoChunksAnalyzer(BaseAnalyzer):
    name          = "I/O Chunks (onstat -g iof + onstat -D)"
    description   = "Top 20 chunks por io/s y cantidad de dbspaces/chunks activos."
    order         = 3
    output_file   = "i_o_chunks.txt"
    file_patterns = ["onstat.g.iof", "onstat_D", "onstat.D"]

    def analyze_to_file(self, files: dict, out):
        iof_path = files.get("onstat.g.iof") or files.get("onstat_g_iof")
        d_path   = files.get("onstat.D") or files.get("onstat_D")

        iof_lines = self.read_file(iof_path) if iof_path else []
        d_lines   = self.read_file(d_path)   if d_path   else []

        for ctx, block in self.split_into_blocks(iof_lines or d_lines):
            # Encabezado del servidor (de iof si hay, sino de D)
            server_line = self._extract_server_line(iof_lines or d_lines)
            if server_line:
                print(server_line, file=out)
            print(file=out)

            # --- Sección iof ---
            if iof_lines:
                chunks = self._parse_iof(iof_lines)
                top20  = sorted(chunks, key=lambda x: x["ios"], reverse=True)[:20]

                print("TOP 20 CHUNKS POR io/s", file=out)
                print("=" * 80, file=out)
                print(f"{'gfd':<5} {'pathname':<25} {'bytes read':>15} {'page reads':>12} {'bytes write':>15} {'page writes':>12} {'io/s':>8}", file=out)
                print("-" * 80, file=out)
                for c in top20:
                    print(f"{c['gfd']:<5} {c['pathname']:<25} {c['bytes_read']:>15} {c['page_reads']:>12} {c['bytes_write']:>15} {c['page_writes']:>12} {c['ios']:>8.1f}", file=out)
                print(file=out)
            else:
                print("onstat -g iof no encontrado.", file=out)
                print(file=out)

            # --- Sección onstat -D ---
            if d_lines:
                dbspaces, chunks_count = self._parse_D(d_lines)
                print("DBSPACES Y CHUNKS ACTIVOS", file=out)
                print("=" * 40, file=out)
                if dbspaces is not None:
                    print(f"Dbspaces: {dbspaces} active", file=out)
                else:
                    print("Dbspaces: no encontrado", file=out)
                if chunks_count is not None:
                    print(f"Chunks:   {chunks_count} active", file=out)
                else:
                    print("Chunks: no encontrado", file=out)
            else:
                print("onstat -D no encontrado.", file=out)

            # Solo procesamos un bloque (el archivo puede tener varios pero
            # split_into_blocks ya los separa; acá tomamos el primero)
            break

    def _extract_server_line(self, lines):
        for line in lines:
            s = line.strip()
            if s.startswith("IBM Informix"):
                return s
        return None

    def _parse_iof(self, lines):
        chunks = []
        pattern = re.compile(r'^(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)')
        for line in lines:
            m = pattern.match(line.strip())
            if m:
                chunks.append({
                    "gfd":         m.group(1),
                    "pathname":    m.group(2),
                    "bytes_read":  int(m.group(3)),
                    "page_reads":  int(m.group(4)),
                    "bytes_write": int(m.group(5)),
                    "page_writes": int(m.group(6)),
                    "ios":         float(m.group(7)),
                })
        return chunks

    def _parse_D(self, lines):
        dbspaces = chunks = None
        pattern = re.compile(r'^\s*(\d+)\s+active,\s+\d+\s+maximum')
        matches = []
        for line in lines:
            m = pattern.match(line)
            if m:
                matches.append(int(m.group(1)))
        if len(matches) >= 1:
            dbspaces = matches[0]
        if len(matches) >= 2:
            chunks = matches[1]
        return dbspaces, chunks
