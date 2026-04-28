import re
from analyzers.base import BaseAnalyzer


class ReplicacionAnalyzer(BaseAnalyzer):
    name          = "Replicación (onstat -g cluster)"
    description   = "Analiza estado de replicación: primario y secundarios."
    order         = 9
    output_file   = "replicacion.txt"
    file_patterns = ["onstat.g.cluster", "onstat_g_cluster"]

    def analyze_to_file(self, files: dict, out):
        path = files.get("onstat.g.cluster") or files.get("onstat_g_cluster")
        lines = self.read_file(path)
        for ctx, block in self.split_into_blocks(lines):
            self._analizar_bloque(block, out)
            break

    def _analizar_bloque(self, lines, out):
        # Encabezado
        server_line = next((l.strip() for l in lines if l.strip().startswith("IBM Informix")), None)
        date_line   = next((l.strip() for l in lines if re.match(r'^\d{4}-\d{2}-\d{2}', l.strip())), None)
        if server_line:
            print(server_line, file=out)
        if date_line:
            print(date_line, file=out)
        print(file=out)

        # Separar bloques por línea de guiones
        servers = self._split_servers(lines)

        if not servers:
            print("No se encontró información de servidores en la salida.", file=out)
            return

        primary     = servers[0]
        secondaries = servers[1:]

        # ── Primario ──────────────────────────────────────────────
        prim_name    = self._field(primary, r'Primary Server\s*:\s*(.+)')
        prim_log_raw = self._field(primary, r'Current Log Page\s*:\s*(.+)')
        prim_log_id, prim_log_page = self._parse_log(prim_log_raw)

        print("Primario:", file=out)
        print(f"  Server Name      : {prim_name or 'N/A'}", file=out)
        print(f"  Current Log Page : {prim_log_raw or 'N/A'}", file=out)
        print(file=out)

        # ── Secundarios ───────────────────────────────────────────
        if not secondaries:
            print("Secundarios:", file=out)
            print("  ALERTA: No se encontraron servidores secundarios.", file=out)
            print(file=out)
            return

        for i, sec in enumerate(secondaries, start=1):
            sec_name   = self._field(sec, r'server name\s*:\s*(.+)')
            sec_type   = self._field(sec, r'type\s*:\s*(.+)')
            sec_conn   = self._field(sec, r'connection status\s*:\s*(.+)')
            sec_status = self._field(sec, r'server status\s*:\s*(.+)')
            sec_acked  = self._field(sec, r'Last log page acked \(log id, page\)\s*:\s*(.+)')
            sec_log_id, sec_log_page = self._parse_log(sec_acked)

            label = "Secundarios" if i == 1 else f"Servidor {i}"
            print(f"{label}:", file=out)
            print(f"  Server Name          : {sec_name or 'N/A'}", file=out)
            print(f"  Modo de replicación  : {sec_type or 'N/A'}", file=out)
            print(f"  Conexión             : {sec_conn or 'N/A'}", file=out)
            print(f"  Estado               : {sec_status or 'N/A'}", file=out)

            # Diferencia de logs respecto al primario
            if prim_log_id is not None and sec_log_id is not None:
                diff_logs  = prim_log_id - sec_log_id
                diff_pages = prim_log_page - sec_log_page
                if diff_logs == 0:
                    print(f"  Distancia al primario: Mismo log, a {abs(diff_pages)} páginas del primario.", file=out)
                else:
                    print(f"  Distancia al primario: A {diff_logs} log(s) del primario.", file=out)
                    if "HDR" in (sec_type or "") and diff_logs >= 2:
                        print(f"  ALERTA: El secundario está a {diff_logs} logs de distancia del primario.", file=out)
            else:
                print("  Distancia al primario: No se pudo calcular (datos insuficientes).", file=out)

            print(file=out)

    def _split_servers(self, lines):
        separator = re.compile(r'^-{10,}')
        blocks = []
        current = []
        for line in lines:
            if separator.match(line.strip()):
                if current:
                    blocks.append(current)
                current = []
            else:
                current.append(line)
        if current:
            blocks.append(current)
        return [b for b in blocks if any(s.strip() for s in b)]

    def _field(self, lines, pattern):
        for line in lines:
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        return None

    def _parse_log(self, value):
        if not value:
            return None, None
        m = re.match(r'(\d+)\s*,\s*(\d+)', value.strip())
        if m:
            return int(m.group(1)), int(m.group(2))
        return None, None
