"""DNS query-response transaction correlation and service mapping."""

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

from network_twin.models.intelligence import EvidenceRecord, EvidenceType

logger = logging.getLogger(__name__)


class DnsTransaction:
    def __init__(self, tx_id: int, qname: str, client_ip: str, query_time: datetime):
        self.tx_id = tx_id
        self.qname = qname
        self.client_ip = client_ip
        self.query_time = query_time
        self.resolved_ips: list[str] = []
        self.response_time: datetime | None = None
        self.rcode: str = "NOERROR"
        self.is_matched: bool = False


class DnsCorrelator:
    """Correlates DNS transactions, domain-to-IP resolutions, and flows."""

    def __init__(self):
        # Key: (tx_id, qname) -> DnsTransaction
        self._pending_queries: dict[tuple[int, str], DnsTransaction] = {}
        # Key: ip_address -> set of hostnames
        self._ip_to_hostnames: dict[str, set[str]] = {}
        # Completed transactions
        self._completed_transactions: list[DnsTransaction] = []

    def record_query(
        self,
        tx_id: int,
        qname: str,
        client_ip: str,
        timestamp: datetime,
    ) -> DnsTransaction:
        key = (tx_id, qname.lower().strip("."))
        tx = DnsTransaction(tx_id=tx_id, qname=qname, client_ip=client_ip, query_time=timestamp)
        self._pending_queries[key] = tx
        return tx

    def record_response(
        self,
        tx_id: int,
        qname: str,
        server_ip: str,
        answers: list[str],
        timestamp: datetime,
        source_id: str,
    ) -> tuple[DnsTransaction | None, list[EvidenceRecord]]:
        clean_qname = qname.lower().strip(".")
        key = (tx_id, clean_qname)
        evidence_list: list[EvidenceRecord] = []

        tx = self._pending_queries.pop(key, None)
        if not tx:
            # Unmatched query or late response
            tx = DnsTransaction(tx_id=tx_id, qname=qname, client_ip="UNKNOWN", query_time=timestamp)

        tx.response_time = timestamp
        tx.resolved_ips = answers
        tx.is_matched = True
        self._completed_transactions.append(tx)

        # Map IP to hostnames and emit evidence
        for ans_ip in answers:
            if ans_ip not in self._ip_to_hostnames:
                self._ip_to_hostnames[ans_ip] = set()
            self._ip_to_hostnames[ans_ip].add(clean_qname)

            ev_id = f"ev-dns-{hashlib.sha256(f'{clean_qname}:{ans_ip}:{source_id}'.encode()).hexdigest()[:12]}"
            ev = EvidenceRecord(
                evidence_id=ev_id,
                evidence_type=EvidenceType.DNS_OBSERVED,
                source_type="dns_resolution",
                source_artifact_id=source_id,
                observation_timestamp=timestamp,
                ingestion_timestamp=datetime.now(UTC),
                src_ref=clean_qname,
                dst_ref=ans_ip,
                parser_status="ok",
                confidence=0.95,
                provenance=f"DNS Response from resolver {server_ip} for {clean_qname} -> {ans_ip}",
                details={
                    "tx_id": tx_id,
                    "qname": clean_qname,
                    "resolver_ip": server_ip,
                    "resolved_ip": ans_ip,
                },
            )
            evidence_list.append(ev)

        return tx, evidence_list

    def get_hostnames_for_ip(self, ip_str: str) -> list[str]:
        return sorted(list(self._ip_to_hostnames.get(ip_str.strip(), set())))

    def list_completed_transactions(self) -> list[dict[str, Any]]:
        return [
            {
                "tx_id": t.tx_id,
                "qname": t.qname,
                "client_ip": t.client_ip,
                "query_time": t.query_time.isoformat(),
                "response_time": t.response_time.isoformat() if t.response_time else None,
                "resolved_ips": t.resolved_ips,
                "is_matched": t.is_matched,
            }
            for t in self._completed_transactions
        ]


dns_correlator = DnsCorrelator()
