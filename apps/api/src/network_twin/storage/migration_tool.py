"""Data Migration Utility: Migrates persistent data from SQLite to PostgreSQL.

Provides table-by-table ETL with transactional integrity and reconciliation checks.
Usage:
    python -m network_twin.storage.migration_tool [--sqlite-path PATH] [--pg-url URL]
"""

from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
from pathlib import Path
from typing import Any

from network_twin.config import AppSettings, settings
from network_twin.storage.db_engine import DatabaseEngine
from network_twin.storage.postgres_schema import POSTGRES_SCHEMA_V9_DDL

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("migration_tool")

# Order respecting foreign key constraints
TABLE_MIGRATION_ORDER = [
    "captures",
    "analysis_jobs",
    "assets",
    "network_segments",
    "services",
    "evidence_records",
    "communication_relationships",
    "topology_snapshots",
    "snapshot_nodes",
    "snapshot_edges",
    "imported_configurations",
    "network_models",
    "simulation_scenarios",
    "security_invariants",
    "verification_runs",
    "counterfactual_results",
    "test_campaigns",
    "test_cases",
    "test_findings",
    "execution_results",
    "regression_fixtures",
    "protocol_sequences",
    "sequence_findings",
    "sequence_regressions",
    "predictive_datasets",
    "model_artifacts",
    "prediction_records",
    "benchmark_runs",
    "benchmark_metrics",
    "investigation_cases",
    "investigation_executions",
]


# Primary key mappings for conflict resolution
TABLE_PRIMARY_KEYS: dict[str, str] = {
    "snapshot_nodes": "snapshot_id, node_id",
    "snapshot_edges": "snapshot_id, edge_id",
}


class MigrationReconciliationReport:
    """Stores reconciliation counts for each migrated table."""

    def __init__(self):
        self.results: list[dict[str, Any]] = []

    def record(self, table: str, sqlite_count: int, pg_count: int, migrated: int) -> None:
        status = "OK" if sqlite_count == pg_count or pg_count >= sqlite_count else "MISMATCH"
        self.results.append(
            {
                "table": table,
                "sqlite_count": sqlite_count,
                "migrated": migrated,
                "pg_count": pg_count,
                "status": status,
            }
        )

    def print_summary(self) -> bool:
        print("\n" + "=" * 80)
        print("SQLITE -> POSTGRESQL MIGRATION RECONCILIATION REPORT")
        print("=" * 80)
        print(f"{'Table Name':<32} {'SQLite Rows':<14} {'Migrated':<12} {'Postgres Rows':<14} {'Status':<8}")
        print("-" * 80)

        all_ok = True
        total_sqlite = 0
        total_migrated = 0
        total_pg = 0

        for r in self.results:
            print(f"{r['table']:<32} {r['sqlite_count']:<14} {r['migrated']:<12} {r['pg_count']:<14} {r['status']:<8}")
            total_sqlite += r["sqlite_count"]
            total_migrated += r["migrated"]
            total_pg += r["pg_count"]
            if r["status"] != "OK":
                all_ok = False

        print("-" * 80)
        print(f"{'TOTAL':<32} {total_sqlite:<14} {total_migrated:<12} {total_pg:<14} {'OK' if all_ok else 'WARN':<8}")
        print("=" * 80 + "\n")
        return all_ok


def migrate_sqlite_to_postgres(sqlite_path: Path, pg_url: str) -> bool:
    """Migrate all data from SQLite database to PostgreSQL."""
    if not sqlite_path.exists():
        logger.error("Source SQLite database does not exist: %s", sqlite_path)
        return False

    logger.info("Connecting to source SQLite database: %s", sqlite_path)
    sqlite_conn = sqlite3.connect(str(sqlite_path))
    sqlite_conn.row_factory = sqlite3.Row

    logger.info("Connecting to target PostgreSQL database: %s", pg_url)
    target_engine = DatabaseEngine(AppSettings(database_url=pg_url))
    if not target_engine.is_connected:
        logger.error("Cannot connect to target PostgreSQL database: %s", target_engine.last_error)
        sqlite_conn.close()
        return False

    # Ensure PostgreSQL schema is initialized
    with target_engine.get_connection() as pg_conn:
        pg_conn.execute(POSTGRES_SCHEMA_V9_DDL)
        pg_conn.commit()

    report = MigrationReconciliationReport()

    try:
        with target_engine.get_connection() as pg_conn:
            for table in TABLE_MIGRATION_ORDER:
                # Check if table exists in SQLite
                cur = sqlite_conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table,))
                if not cur.fetchone():
                    logger.debug("Table %s does not exist in SQLite, skipping", table)
                    report.record(table, 0, 0, 0)
                    continue

                # Read all rows from SQLite
                cur = sqlite_conn.execute(f"SELECT * FROM {table};")
                rows = cur.fetchall()
                sqlite_count = len(rows)

                if sqlite_count == 0:
                    report.record(table, 0, 0, 0)
                    continue

                col_names = [col[0] for col in cur.description]
                cols_str = ", ".join(col_names)
                placeholders = ", ".join(["%s"] * len(col_names))

                # Primary key for conflict handling
                pk_clause = TABLE_PRIMARY_KEYS.get(table, col_names[0])

                insert_sql = (
                    f"INSERT INTO {table} ({cols_str}) VALUES ({placeholders}) ON CONFLICT ({pk_clause}) DO NOTHING;"
                )

                values_list = [tuple(row) for row in rows]
                with pg_conn.cursor() as pg_cur:
                    pg_cur.executemany(insert_sql, values_list)

                # Reconcile count in Postgres
                cur_pg = pg_conn.execute(f"SELECT COUNT(*) FROM {table};")
                pg_count = cur_pg.fetchone()[0]

                report.record(table, sqlite_count, pg_count, sqlite_count)
                logger.info("Migrated %s: %d SQLite rows -> %d PostgreSQL rows", table, sqlite_count, pg_count)

            pg_conn.commit()

    finally:
        sqlite_conn.close()
        target_engine.close()

    success = report.print_summary()
    return success


def main():
    parser = argparse.ArgumentParser(description="Migrate Protocol Digital Twin SQLite catalog to PostgreSQL")
    parser.add_argument(
        "--sqlite-path",
        type=Path,
        default=Path("data/metadata.db"),
        help="Path to source SQLite metadata.db (default: data/metadata.db)",
    )
    parser.add_argument(
        "--pg-url",
        type=str,
        default=settings.database_url or "postgresql://postgres@127.0.0.1:54333/network_twin",
        help="PostgreSQL connection URL (default: NTWIN_DATABASE_URL or local default)",
    )

    args = parser.parse_args()
    success = migrate_sqlite_to_postgres(args.sqlite_path, args.pg_url)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
