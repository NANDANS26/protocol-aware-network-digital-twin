"""Analytical Event Store using DuckDB and Parquet for fast columnar querying."""

import logging
from pathlib import Path
from typing import Any

import duckdb

from network_twin.config import AppSettings, settings

logger = logging.getLogger(__name__)


class AnalyticsStore:
    """Manages Parquet-backed event archives and high-speed DuckDB SQL analytical queries."""

    def __init__(self, config: AppSettings = settings):
        self.config = config
        self.analytics_dir = Path(self.config.data_dir) / "analytics"
        self.analytics_dir.mkdir(parents=True, exist_ok=True)

    def get_parquet_path(self, job_id: str) -> Path:
        return self.analytics_dir / f"{job_id}.parquet"

    def convert_jsonl_to_parquet(self, job_id: str, jsonl_path: Path) -> Path:
        """Converts raw C++-emitted JSONL event file to indexed columnar Parquet with normalized columns."""
        if not jsonl_path.is_file():
            raise FileNotFoundError(f"JSONL event source file not found: {jsonl_path}")

        target_parquet = self.get_parquet_path(job_id)
        escaped_jsonl = str(jsonl_path).replace("\\", "/")
        escaped_parquet = str(target_parquet).replace("\\", "/")

        conn = duckdb.connect(database=":memory:")
        try:
            # Inspect columns present in JSON file to build safe projection
            desc = conn.execute(f"DESCRIBE SELECT * FROM read_json_auto('{escaped_jsonl}')").fetchall()
            cols = {row[0].lower() for row in desc}

            src_ip_expr = "network_layer.source_ip" if "network_layer" in cols else ("src_ip" if "src_ip" in cols else "NULL")
            dst_ip_expr = "network_layer.destination_ip" if "network_layer" in cols else ("dst_ip" if "dst_ip" in cols else "NULL")
            src_port_expr = "transport_layer.source_port" if "transport_layer" in cols else ("src_port" if "src_port" in cols else "NULL")
            dst_port_expr = "transport_layer.destination_port" if "transport_layer" in cols else ("dst_port" if "dst_port" in cols else "NULL")

            if "transport_layer" in cols:
                proto_expr = "coalesce(transport_layer.protocol, 'OTHER')"
            elif "transport_protocol" in cols:
                proto_expr = "transport_protocol"
            elif "ip_proto" in cols:
                proto_expr = "ip_proto"
            else:
                proto_expr = "'OTHER'"

            wire_len_expr = "provenance.wire_length_bytes" if "provenance" in cols else ("payload_length_bytes" if "payload_length_bytes" in cols else "0")
            status_expr = "parser_status.status" if "parser_status" in cols else "'ok'"

            sql = f"""
            COPY (
                SELECT
                    event_id,
                    timestamp_ns,
                    timestamp_iso,
                    {src_ip_expr} as src_ip,
                    {dst_ip_expr} as dst_ip,
                    {src_port_expr} as src_port,
                    {dst_port_expr} as dst_port,
                    {proto_expr} as transport_protocol,
                    {wire_len_expr} as payload_length_bytes,
                    {status_expr} as parser_status
                FROM read_json_auto('{escaped_jsonl}')
            ) TO '{escaped_parquet}' (FORMAT PARQUET, COMPRESSION ZSTD);
            """
            conn.execute(sql)
            logger.info("Created Parquet analytical store for job %s at %s", job_id, target_parquet)
            return target_parquet
        finally:
            conn.close()

    def query_events(
        self,
        job_id: str,
        limit: int = 100,
        offset: int = 0,
        protocol: str | None = None,
        ip: str | None = None,
    ) -> list[dict[str, Any]]:
        """Queries events directly from the Parquet file via DuckDB."""
        parquet_file = self.get_parquet_path(job_id)
        if not parquet_file.is_file():
            return []

        escaped_parquet = str(parquet_file).replace("\\", "/")
        conn = duckdb.connect(database=":memory:")
        try:
            where_clauses = ["1=1"]
            params: list[Any] = []

            if protocol:
                where_clauses.append("upper(transport_protocol) = upper(?)")
                params.append(protocol)
            if ip:
                where_clauses.append("(src_ip = ? OR dst_ip = ?)")
                params.extend([ip, ip])

            where_str = " AND ".join(where_clauses)
            sql = f"""
            SELECT
                event_id,
                timestamp_ns,
                timestamp_iso,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                transport_protocol,
                payload_length_bytes,
                parser_status
            FROM read_parquet('{escaped_parquet}')
            WHERE {where_str}
            ORDER BY timestamp_ns ASC
            LIMIT ? OFFSET ?;
            """
            params.extend([limit, offset])

            cur = conn.execute(sql, params)
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
            return [dict(zip(cols, row, strict=False)) for row in rows]
        finally:
            conn.close()

    def query_top_talkers(self, job_id: str, limit: int = 10) -> list[dict[str, Any]]:
        """Aggregates source IP bandwidth and packet counts using DuckDB."""
        parquet_file = self.get_parquet_path(job_id)
        if not parquet_file.is_file():
            return []

        escaped_parquet = str(parquet_file).replace("\\", "/")
        conn = duckdb.connect(database=":memory:")
        try:
            sql = f"""
            SELECT
                src_ip as ip_address,
                count(*) as packet_count,
                sum(coalesce(payload_length_bytes, 0)) as total_bytes,
                count(distinct dst_ip) as distinct_peers
            FROM read_parquet('{escaped_parquet}')
            WHERE src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            ORDER BY packet_count DESC
            LIMIT ?;
            """
            cur = conn.execute(sql, [limit])
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
            return [dict(zip(cols, row, strict=False)) for row in rows]
        finally:
            conn.close()

    def query_protocol_breakdown(self, job_id: str) -> list[dict[str, Any]]:
        """Computes transport protocol distribution from Parquet."""
        parquet_file = self.get_parquet_path(job_id)
        if not parquet_file.is_file():
            return []

        escaped_parquet = str(parquet_file).replace("\\", "/")
        conn = duckdb.connect(database=":memory:")
        try:
            sql = f"""
            SELECT
                coalesce(transport_protocol, 'OTHER') as protocol,
                count(*) as packet_count,
                sum(coalesce(payload_length_bytes, 0)) as total_bytes
            FROM read_parquet('{escaped_parquet}')
            GROUP BY transport_protocol
            ORDER BY packet_count DESC;
            """
            cur = conn.execute(sql)
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
            return [dict(zip(cols, row, strict=False)) for row in rows]
        finally:
            conn.close()


analytics_store = AnalyticsStore()
