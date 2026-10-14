"""
HTTP Terminator One-Click Launcher (start.py):
Spawns both:
1. The local Protocol Test Lab Server (127.0.0.1:8080) in the background.
2. The Autonomous Flaw Hunter with local Google Gemma ModelFusion (or the MCP Server if requested).

Starts with the canonical Model Context Protocol (MCP) RFC specification,
ingests fragments, evaluates cross-connection queue contamination,
and executes dangling-byte RQP weaponization.
"""

import argparse
import os
import signal
import sys
import time

from continuous_scanner import ContinuousFlawHunter
from mcp_server import TerminatorMCPServer
from test_lab_server import TestLabServer

# Ensure Windows terminal doesn't crash on UTF-8 RFC characters or BOMs
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HTTP Terminator: One-Click Dual Launcher (Test Lab + Flaw Hunter / MCP)",
        epilog="""
===============================================================================
USAGE EXAMPLES:
===============================================================================

1. Launch local Test Lab Server + Autonomous Flaw Hunter (starts with RFC 9112):
   python start.py

2. Target a single RFC against the local Test Lab:
   python start.py --rfc 9112 --variants 4

3. Target a remote HTTPS reverse proxy / terminator (bypasses local mock lab):
   python start.py --host target.example.com --port 443 --tls --no-lab

4. Offline RFC ingestion & probe generation only (no packets sent to any host):
   python start.py --comb-only --max-rfcs 25

5. Filter active RFCs by keyword (e.g. chunked, trailer, websocket):
   python start.py --keywords "chunked,trailer,websocket" --max-rfcs 10

6. Launch the Model Context Protocol (MCP) JSON-RPC server over stdio:
   python start.py --mcp
===============================================================================
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--port", type=int, default=8080, help="Test lab server port (default: 8080)")
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("--model", default="gemma2:2b", help="Base model (default: gemma2:2b)")
    parser.add_argument("--no-fusion", dest="fusion", action="store_false", help="Disable multi-model panel fusion")
    parser.set_defaults(fusion=True)
    parser.add_argument("--max-rfcs", type=int, default=None, help="Maximum RFCs to cycle through (default: all when --all-active, else 10)")
    parser.add_argument("--fragments", type=int, default=2, help="Fragments per RFC (default: 2)")
    parser.add_argument("--variants", type=int, default=2, help="Permutations per probe (default: 2)")
    parser.add_argument("--keep-going", action="store_true", help="Keep running continuously after finding flaws")
    parser.add_argument("--kettle", dest="kettle", action="store_true", default=True, help="Target James Kettle's curated 138 HTTP and SMTP RFC corpus (default: True)")
    parser.add_argument("--all-active", action="store_true", help="Comb through all 1,259 active RFCs instead of the 138 Kettle corpus")
    parser.add_argument("--unrestricted", action="store_true", help="Scan every active RFC without keyword filtering")
    parser.add_argument("--keywords", default=None, help="Comma-separated keywords to filter active RFCs")
    parser.add_argument("--rfc", default=None, help="Target a specific RFC only (e.g. --rfc 9112 or --rfc MCP)")
    parser.add_argument("--no-resume", dest="resume", action="store_false", help="Do not skip previously scanned RFCs")
    parser.set_defaults(resume=True)
    parser.add_argument("-v", "--verbose", action="store_true", default=True, help="Display live HTTP request/response host activity trace")
    parser.add_argument("--cisco", dest="cisco", action="store_true", default=True, help="Use Cisco Foundation-Sec-8B as the exploit boundary specialist (default: True)")
    parser.add_argument("--no-cisco", dest="cisco", action="store_false", help="Disable Cisco model and fallback to Qwen")
    parser.add_argument("--tls", action="store_true", help="Force TLS/HTTPS for target connections")
    parser.add_argument("--no-lab", action="store_true", help="Do not spawn the built-in mock lab server; target an existing server instead")
    parser.add_argument("--comb-only", "--offline", dest="comb_only", action="store_true", help="Comb through RFCs, chunk fragments, and generate probes into database without testing hosts")
    parser.add_argument("--mcp", action="store_true", help="Launch the MCP server instead of the continuous hunter")
    parser.add_argument("--targets", default=None, help="Comma-separated target terminators (e.g. '127.0.0.1:8080,127.0.0.1:8081,proxy2.local:443')")
    parser.add_argument("--terminators", default="all", help="Comma-separated terminator categories: 'line,chunk,framing,cross_protocol,crlf_rhi,h2_gateway' or 'all' (default: all)")
    parser.add_argument("--mode", default=None, choices=["hunt", "ruler", "lab", "offline", "comb-only", "mcp", "dream", "build", "ui"], help="Execution mode (default: hunt, or lab+hunt if local)")
    parser.add_argument("--random-port", "--high-port", action="store_true", help="Use a high random available port for the test lab server / UI")
    parser.add_argument("--ui", action="store_true", help="Launch the interactive research dashboard web UI on a high random available port")
    return parser


def parse_arguments(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if isinstance(args.targets, str):
        args.targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    if isinstance(args.terminators, str):
        if args.terminators.lower() == "all":
            args.terminators = ["all"]
        else:
            args.terminators = [t.strip() for t in args.terminators.split(",") if t.strip()]
    return args


def main():
    args = parse_arguments()

    # Determine TLS requirement (automatic for port 443)
    use_tls = args.tls or (args.port == 443)
    if args.host in ("0.0.0.0", "::"):
        print("[!] ERROR: Target destination address cannot be 0.0.0.0 or :: (INADDR_ANY bind address).")
        print("[*] For local protocol research, please specify --host 127.0.0.1 or --host localhost.")
        sys.exit(1)
    is_local_target = args.host in ("127.0.0.1", "localhost", "::1", "[::1]")

    print("=" * 70)
    print("  HTTP TERMINATOR: AUTONOMOUS RESEARCH FACTORY")
    print("  Architecture: PortSwigger DEF CON 34 / Black Hat USA 2026")
    print("  Engine: Google Gemma 2 + ModelFusion via Ollama (Zero Cost 24/7)")
    print("  Starting Spec: RFC 9112 (HTTP/1.1 Message Syntax & Framing - Primary Terminator Spec)")
    print("=" * 70)

    # Parse multiple target terminators if provided
    target_list = []
    if args.targets:
        for t_str in args.targets.split(","):
            t_str = t_str.strip()
            if not t_str:
                continue
            if "://" in t_str:
                t_proto, t_rest = t_str.split("://", 1)
                t_tls = t_proto.lower() == "https"
            else:
                t_rest = t_str
                t_tls = args.tls or (":443" in t_rest)
            if ":" in t_rest:
                h, p = t_rest.split(":", 1)
                target_list.append((h.strip(), int(p.strip()), t_tls))
            else:
                target_list.append((t_rest.strip(), 443 if t_tls else 80, t_tls))
    else:
        target_list = [(args.host, args.port, use_tls)]

    # Handle mode overrides
    if args.mode:
        m = args.mode.lower().strip()
        if m == "mcp":
            args.mcp = True
        elif m in ("offline", "comb-only"):
            args.comb_only = True

    # 1. Start Local Protocol Test Lab Server (if first target is local 8080 and not disabled, or if --random-port is given)
    lab_server = None
    first_host, first_port, first_tls = target_list[0]
    is_first_local = first_host in ("127.0.0.1", "localhost", "::1", "[::1]")
    should_spawn_lab = is_first_local and (first_port == 8080 or args.random_port) and not args.no_lab and not args.comb_only and not (args.ui or args.mode == "ui")

    if args.comb_only:
        print("\n[+] Step 1: Mode: Offline RFC Ingestion & Discovery")
        print("    (Host evaluation bypassed - generating and banking probes into database only)")
    elif should_spawn_lab:
        bind_port = 0 if args.random_port else first_port
        lab_server = TestLabServer(host=first_host, port=bind_port)
        try:
            lab_server.start()
            first_port = lab_server.port
            target_list[0] = (first_host, first_port, first_tls)
            time.sleep(0.4)
            print(f"\n[+] Step 1: Initializing local Protocol Test Lab on http://{first_host}:{first_port}...")
        except Exception as e:
            print(f"[!] Failed to bind lab server: {e}")
            sys.exit(1)
    else:
        print(f"\n[+] Step 1: Configured {len(target_list)} Target Terminator(s):")
        for idx, (h, p, tls_f) in enumerate(target_list, 1):
            proto = "https" if tls_f else "http"
            print(f"    [{idx}] {proto}://{h}:{p}")

    # Graceful shutdown handler
    def shutdown(sig=None, frame=None):
        print("\n\n[*] Shutting down HTTP Terminator...")
        if lab_server:
            lab_server.stop()
        print("[+] All services halted safely.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # 2. Launch Hunter or MCP Server
    try:
        if args.mcp:
            print(f"\n[+] Step 2: Launching Model Context Protocol (MCP) Server over stdio...")
            mcp_server = TerminatorMCPServer()
            mcp_server.run_stdio()
        elif args.ui or args.mode == "ui":
            ui_port = 0 if (args.random_port or args.ui) else args.port
            lab_server = TestLabServer(host=first_host if is_first_local else "127.0.0.1", port=ui_port)
            lab_server.start()
            print(f"\n{'='*70}")
            print(f"  HTTP TERMINATOR: RESEARCH DASHBOARD UI")
            print(f"{'='*70}")
            print(f"  [+] UI Server Active on High Random Port : {lab_server.port}")
            print(f"  [+] Local Web UI URL                    : http://127.0.0.1:{lab_server.port}/")
            print(f"  [+] Interactive Dashboard Viewport      : http://127.0.0.1:{lab_server.port}/dashboard")
            print(f"{'='*70}")
            print("  Press Ctrl+C to halt the UI server.\n")
            while True:
                time.sleep(1)
        elif args.mode == "lab":
            print(f"\n[+] Test Lab Server running on http://{first_host}:{first_port}. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
        else:
            print(f"\n[+] Step 2: Launching Continuous Flaw Hunter across {len(target_list)} terminator(s)...")
            sec_model = "fenkohq/foundation-sec-8b:latest" if args.cisco else None
            keyword_list = [k.strip() for k in args.keywords.split(",")] if args.keywords else None
            max_limit = args.max_rfcs

            for idx, (t_host, t_port, t_tls) in enumerate(target_list, 1):
                if len(target_list) > 1:
                    proto = "https" if t_tls else "http"
                    print(f"\n{'='*70}\n[+] TARGET #{idx}: {proto}://{t_host}:{t_port}\n{'='*70}")

                hunter = ContinuousFlawHunter(
                    target_host=t_host,
                    target_port=t_port,
                    use_tls=t_tls,
                    preferred_model=args.model,
                    use_fusion=args.fusion,
                    verbose=args.verbose,
                    sec_model=sec_model,
                )

                flaws = hunter.run_until_flaw(
                    max_rfcs=max_limit,
                    fragments_per_rfc=args.fragments,
                    permutations_per_probe=args.variants,
                    stop_on_first_flaw=not args.keep_going,
                    all_active=args.all_active,
                    unrestricted=args.unrestricted,
                    kettle=args.kettle,
                    keywords=keyword_list,
                    resume=args.resume,
                    target_rfc=args.rfc,
                    comb_only=args.comb_only,
                )
                if args.comb_only:
                    print(f"\n[+] RFC Ingestion complete. Candidate triggers saved to database.")
                    break  # Offline mode doesn't need to re-run per target host
                else:
                    print(f"\n[*] Flaw hunt cycle complete for {t_host}:{t_port}. Discoveries: {len(flaws)}")

    except KeyboardInterrupt:
        shutdown()
    except Exception as e:
        import traceback
        print(f"\n[!] Runtime Error: {e}")
        traceback.print_exc()
        shutdown()


if __name__ == "__main__":
    main()
