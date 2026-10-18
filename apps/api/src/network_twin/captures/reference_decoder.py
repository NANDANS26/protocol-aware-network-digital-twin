"""
Independent Reference Protocol Decoder for Differential Verification.
Written in pure Python using standard struct parsing strictly following RFC specifications.
Serves as an independent mathematical oracle for differential assertions against the C++ systems engine.
"""

import ipaddress
import struct
from typing import Any


class ReferenceDecoder:
    """Zero-dependency pure-Python reference decoder for standard network protocols."""

    @staticmethod
    def parse_pcap_packets(data: bytes) -> list[tuple[int, int, bytes]]:
        """Parses raw classic PCAP bytes into list of (ts_sec, ts_usec, packet_bytes)."""
        if len(data) < 24:
            return []
        magic = struct.unpack("!I", data[:4])[0]
        is_big_endian = magic == 0xA1B2C3D4
        is_little_endian = magic == 0xD4C3B2A1

        if not (is_big_endian or is_little_endian):
            raise ValueError(f"Unsupported PCAP magic header: 0x{magic:08x}")

        endian = ">" if is_big_endian else "<"
        offset = 24
        packets = []

        while offset + 16 <= len(data):
            ts_sec, ts_usec, cap_len, orig_len = struct.unpack(
                f"{endian}IIII", data[offset : offset + 16]
            )
            offset += 16
            if offset + cap_len > len(data):
                break
            pkt_bytes = data[offset : offset + cap_len]
            offset += cap_len
            packets.append((ts_sec, ts_usec, pkt_bytes))

        return packets

    @staticmethod
    def decode_packet(pkt_bytes: bytes) -> dict[str, Any]:
        """Decodes a single packet frame from Layer 2 to Layer 4/7."""
        result: dict[str, Any] = {
            "link_layer": None,
            "network_layer": None,
            "transport_layer": None,
            "application_layer": None,
            "status": "ok",
        }

        if len(pkt_bytes) < 14:
            result["status"] = "malformed"
            result["error"] = "Frame shorter than minimum Ethernet header (14 bytes)"
            return result

        # 1. Ethernet II
        dst_mac = ":".join(f"{b:02x}" for b in pkt_bytes[0:6])
        src_mac = ":".join(f"{b:02x}" for b in pkt_bytes[6:12])
        ether_type = struct.unpack("!H", pkt_bytes[12:14])[0]
        offset = 14

        # 802.1Q VLAN Tag check
        vlan_id = None
        if ether_type == 0x8100:
            if len(pkt_bytes) < offset + 4:
                result["status"] = "malformed"
                return result
            tci, ether_type = struct.unpack("!HH", pkt_bytes[offset : offset + 4])
            vlan_id = tci & 0x0FFF
            offset += 4

        result["link_layer"] = {
            "protocol": "Ethernet",
            "source_mac": src_mac,
            "destination_mac": dst_mac,
            "ether_type": ether_type,
            "vlan_id": vlan_id,
        }

        # 2. Network Layer
        if ether_type == 0x0806:  # ARP
            if len(pkt_bytes) < offset + 28:
                result["status"] = "malformed"
                return result
            hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack(
                "!HHBBH", pkt_bytes[offset : offset + 8]
            )
            s_mac = ":".join(f"{b:02x}" for b in pkt_bytes[offset + 8 : offset + 14])
            s_ip = ".".join(str(b) for b in pkt_bytes[offset + 14 : offset + 18])
            t_mac = ":".join(f"{b:02x}" for b in pkt_bytes[offset + 18 : offset + 24])
            t_ip = ".".join(str(b) for b in pkt_bytes[offset + 24 : offset + 28])

            result["network_layer"] = {
                "protocol": "ARP",
                "opcode": opcode,
                "sender_mac": s_mac,
                "sender_ip": s_ip,
                "target_mac": t_mac,
                "target_ip": t_ip,
            }
            return result

        elif ether_type == 0x0800:  # IPv4
            if len(pkt_bytes) < offset + 20:
                result["status"] = "malformed"
                return result
            v_ihl = pkt_bytes[offset]
            version = (v_ihl >> 4) & 0x0F
            ihl = v_ihl & 0x0F
            if version != 4 or ihl < 5:
                result["status"] = "malformed"
                return result
            ihl_bytes = ihl * 4
            if len(pkt_bytes) < offset + ihl_bytes:
                result["status"] = "malformed"
                return result

            total_length, ident, flags_frag, ttl, proto, cksum = struct.unpack(
                "!HHHBBH", pkt_bytes[offset + 2 : offset + 12]
            )
            src_ip = ".".join(str(b) for b in pkt_bytes[offset + 12 : offset + 16])
            dst_ip = ".".join(str(b) for b in pkt_bytes[offset + 16 : offset + 20])
            flags = (flags_frag >> 13) & 0x07
            frag_offset = (flags_frag & 0x1FFF) * 8
            is_fragment = (flags & 0x01) != 0 or frag_offset > 0

            result["network_layer"] = {
                "protocol": "IPv4",
                "version": 4,
                "ihl": ihl,
                "total_length": total_length,
                "identification": ident,
                "flags": flags,
                "fragment_offset": frag_offset,
                "is_fragment": is_fragment,
                "ttl": ttl,
                "ip_protocol": proto,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
            }

            if is_fragment and frag_offset > 0:
                result["transport_layer"] = {"protocol": "IPv4-Fragment", "fragment_offset": frag_offset}
                return result

            offset += ihl_bytes

            # 3. Transport Layer (IPv4)
            ReferenceDecoder._decode_transport(pkt_bytes, offset, proto, src_ip, dst_ip, result)

        elif ether_type == 0x86DD:  # IPv6
            if len(pkt_bytes) < offset + 40:
                result["status"] = "malformed"
                return result
            vtc_fl, payload_len, next_hdr, hop_limit = struct.unpack(
                "!IHBB", pkt_bytes[offset : offset + 8]
            )
            src_ip = str(ipaddress.IPv6Address(pkt_bytes[offset + 8 : offset + 24]))
            dst_ip = str(ipaddress.IPv6Address(pkt_bytes[offset + 24 : offset + 40]))

            result["network_layer"] = {
                "protocol": "IPv6",
                "version": 6,
                "payload_length": payload_len,
                "next_header": next_hdr,
                "hop_limit": hop_limit,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
            }
            offset += 40

            if next_hdr == 58:  # ICMPv6
                if len(pkt_bytes) >= offset + 4:
                    icmp_type, icmp_code = struct.unpack("!BB", pkt_bytes[offset : offset + 2])
                    result["transport_layer"] = {
                        "protocol": "ICMPv6",
                        "type": icmp_type,
                        "code": icmp_code,
                    }
            else:
                ReferenceDecoder._decode_transport(pkt_bytes, offset, next_hdr, src_ip, dst_ip, result)

        return result

    @staticmethod
    def _decode_transport(
        pkt_bytes: bytes,
        offset: int,
        proto: int,
        src_ip: str,
        dst_ip: str,
        result: dict[str, Any],
    ) -> None:
        if proto == 1:  # ICMP
            if len(pkt_bytes) >= offset + 4:
                icmp_type, icmp_code = struct.unpack("!BB", pkt_bytes[offset : offset + 2])
                result["transport_layer"] = {"protocol": "ICMP", "type": icmp_type, "code": icmp_code}

        elif proto == 6:  # TCP
            if len(pkt_bytes) < offset + 20:
                result["status"] = "truncated"
                return
            src_port, dst_port, seq, ack, offset_res, flags_b, win = struct.unpack(
                "!HHIIBBH", pkt_bytes[offset : offset + 16]
            )
            tcp_header_len = ((offset_res >> 4) & 0x0F) * 4
            if len(pkt_bytes) < offset + tcp_header_len:
                result["status"] = "truncated"
                return

            result["transport_layer"] = {
                "protocol": "TCP",
                "source_port": src_port,
                "destination_port": dst_port,
                "sequence_number": seq,
                "acknowledgment_number": ack,
                "data_offset": tcp_header_len,
                "flags": {
                    "fin": (flags_b & 0x01) != 0,
                    "syn": (flags_b & 0x02) != 0,
                    "rst": (flags_b & 0x04) != 0,
                    "psh": (flags_b & 0x08) != 0,
                    "ack": (flags_b & 0x10) != 0,
                    "urg": (flags_b & 0x20) != 0,
                },
                "window_size": win,
            }

            payload_offset = offset + tcp_header_len
            payload = pkt_bytes[payload_offset:]

            # Check for HTTP or TLS
            if payload:
                if (src_port == 80 or dst_port == 80) and (
                    payload.startswith(b"GET ")
                    or payload.startswith(b"POST ")
                    or payload.startswith(b"HTTP/1.")
                ):
                    first_line = payload.split(b"\r\n")[0].decode("ascii", errors="replace")
                    result["application_layer"] = {
                        "protocol": "HTTP",
                        "first_line": first_line,
                    }
                elif (src_port == 443 or dst_port == 443) and len(payload) >= 5 and payload[0] == 22:
                    # TLS Record
                    rec_type, legacy_ver, rec_len = struct.unpack("!BHH", payload[:5])
                    if len(payload) >= 5 + rec_len and rec_type == 22 and len(payload) > 9:
                        hs_type = payload[5]
                        if hs_type == 1:  # ClientHello
                            sni = ReferenceDecoder._extract_tls_sni(payload[5:])
                            result["application_layer"] = {
                                "protocol": "TLS",
                                "handshake_type": "ClientHello",
                                "server_name": sni,
                            }

        elif proto == 17:  # UDP
            if len(pkt_bytes) < offset + 8:
                result["status"] = "truncated"
                return
            src_port, dst_port, length, cksum = struct.unpack("!HHHH", pkt_bytes[offset : offset + 8])
            result["transport_layer"] = {
                "protocol": "UDP",
                "source_port": src_port,
                "destination_port": dst_port,
                "length": length,
            }

            payload_offset = offset + 8
            payload = pkt_bytes[payload_offset:]

            # DNS Check
            if (src_port == 53 or dst_port == 53) and len(payload) >= 12:
                tx_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
                qname = ReferenceDecoder._extract_dns_qname(payload, 12)
                result["application_layer"] = {
                    "protocol": "DNS",
                    "transaction_id": tx_id,
                    "is_response": (flags & 0x8000) != 0,
                    "qname": qname,
                    "query_count": qd,
                    "answer_count": an,
                }

    @staticmethod
    def _extract_dns_qname(data: bytes, offset: int) -> str:
        parts = []
        visited = set()
        while offset < len(data):
            if offset in visited:
                break
            visited.add(offset)
            length = data[offset]
            if length == 0:
                break
            if (length & 0xC0) == 0xC0:
                # Compression pointer
                if offset + 1 >= len(data):
                    break
                ptr_offset = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
                sub = ReferenceDecoder._extract_dns_qname(data, ptr_offset)
                if sub:
                    parts.append(sub)
                break
            offset += 1
            if offset + length > len(data):
                break
            parts.append(data[offset : offset + length].decode("ascii", errors="replace"))
            offset += length
        return ".".join(parts)

    @staticmethod
    def _extract_tls_sni(hs_payload: bytes) -> str | None:
        """Parses TLS ClientHello payload to extract Server Name Indication (SNI)."""
        try:
            # hs_payload starts at handshake type (1 byte) + 3 bytes length + 2 bytes version + 32 bytes random
            if len(hs_payload) < 38:
                return None
            offset = 4 + 2 + 32  # 38
            # Session ID len
            sess_len = hs_payload[offset]
            offset += 1 + sess_len
            if offset + 2 > len(hs_payload):
                return None
            cipher_len = struct.unpack("!H", hs_payload[offset : offset + 2])[0]
            offset += 2 + cipher_len
            if offset + 1 > len(hs_payload):
                return None
            comp_len = hs_payload[offset]
            offset += 1 + comp_len
            if offset + 2 > len(hs_payload):
                return None
            ext_total_len = struct.unpack("!H", hs_payload[offset : offset + 2])[0]
            offset += 2
            ext_end = offset + ext_total_len

            while offset + 4 <= min(ext_end, len(hs_payload)):
                ext_type, ext_len = struct.unpack("!HH", hs_payload[offset : offset + 4])
                offset += 4
                if ext_type == 0x0000:  # Server Name
                    if offset + 2 <= len(hs_payload):
                        # skip list length (2 bytes) + type (1 byte)
                        name_len = struct.unpack("!H", hs_payload[offset + 3 : offset + 5])[0]
                        sni = hs_payload[offset + 5 : offset + 5 + name_len].decode("utf-8", errors="replace")
                        return sni
                offset += ext_len
        except Exception:
            return None
        return None
