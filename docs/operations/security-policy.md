# Security & Safe Testing Policy

## 1. Core Security Principles

The Protocol-Aware Network Digital Twin platform is designed for research, verification, and defense-in-depth security engineering. The following rules are non-negotiable architectural mandates:

1. **Passive Observation by Default**:
   - The engine operates in passive observation mode by default.
   - It **never** alters live host or network configurations, routing tables, DNS resolvers, or firewall rules automatically.
2. **Quarantine Active Capabilities**:
   - Active testing (such as protocol fuzzing, packet injection, or synthetic load generation) must be explicitly enabled via command-line flags and authorized by configuration.
   - Active testing capabilities must run in isolated network namespaces or sandbox environments.
3. **Zero Hardcoded Secrets**:
   - No passwords, API keys, or private tokens in code, tests, or committed configuration.
   - Configuration is supplied via environment variables (`NTWIN_*`) with strict typing and safe fallbacks.
4. **Zero-Trust Payload Privacy**:
   - High-throughput packet ingestion calculates cryptographic payload hashes (`payload_hash_sha256`) rather than dumping raw sensitive network payloads to logs or databases.
   - Textual previews are limited to sanitized, non-credential header summaries.
5. **Denial-of-Service Defense**:
   - API endpoints enforce bounded payload limits (`Content-Length` checks, max 10MB default) to prevent memory exhaustion.
   - C++ engine buffers enforce strict ring-buffer limits and backpressure handling.
6. **Strict CORS Boundaries**:
   - Production instances forbid wildcard CORS origins (`allow_origins=["*"]`).
   - Only configured development origins (e.g., `localhost:5173`) are permitted in non-production environments.

---

## 2. Live Capture Permissions & Host Safety

- **Windows**: Requires Npcap installed in "WinPcap API-compatible Mode". Must run with explicit administrative permission to bind to physical interfaces.
- **Linux**: Requires `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities or root execution for promiscuous socket capture.
- **Unprivileged Development Mode**: File-based PCAP analysis and synthetic generator modes require zero elevated permissions and are the default for local development and CI testing.

---

## 3. Vulnerability Reporting

See [SECURITY.md](../../SECURITY.md) in the repository root for our responsible disclosure guidelines and reporting workflow.
