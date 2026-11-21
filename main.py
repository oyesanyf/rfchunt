"""
HTTP Terminator: Autonomous Protocol Security Research Factory.
Based on PortSwigger's DEF CON 34 / Black Hat USA 2026 research by James Kettle.

Automates:
1. Dynamic RFC Fetching & Ingestion (canonical + recent HTTP specs).
2. Micro-Inspiration Fragmentation & Anti-Anchoring.
3. Zero-Cost Local Inference with Google Gemma & ModelFusion via Ollama.
4. Systematic Vector Permutations (path nul, dual-matching CL, dangling bytes).
5. Deterministic Evaluation Harness (Connection A/B state contamination).
6. Anomaly Detection Cascade (Text/Binary Blend, Double HTML, Inline Headers, Clean Dual-Responses).
7. Autonomous RQP & Dangling-Byte Technique.
8. Discovery Cascade & Shared-Parser Confusion extrapolation.
"""

import argparse
import contextlib
import os
import sys
import time
from typing import List, Optional

from anomaly_detector import AnomalyDetector
from cascade import DiscoveryCascade
from database import Database
from deterministic_harness import DeterministicHarness
from permutator import VectorPermutator
from probe_generator import ProbeGenerator
from rfc_chunker import RFCChunker
from rfc_fetcher import RFCFetcher
from test_lab_server import TestLabServer
from weaponizer import RQPWeaponizer
from engine.host_containment import HostContainmentManager


def cmd_fetch(args):
    db = Database(args.db)
    fetcher = RFCFetcher(cache_dir=args.cache_dir, db=db)
    try:
        print(f"[+] Fetching core RFC documents (limit={args.count})...")
        core_docs = fetcher.fetch_core_rfcs(limit=args.count)
        print(f"[*] Fetched {len(core_docs)} core RFCs.")

        if args.discover_recent:
            print("[+] Scanning RFC index for newly published protocol specifications...")
            recent_nums = fetcher.discover_recent_rfcs(max_discover=args.discover_recent)
            for num in recent_nums:
                fetcher.fetch_rfc_by_number(num)
    finally:
        if hasattr(fetcher, "client") and hasattr(fetcher.client, "close"):
            fetcher.client.close()
        db.close()


def cmd_chunk(args):
    db = Database(args.db)
    try:
        cursor = db.conn.cursor()
        cursor.execute("SELECT rfc_id, doc_path FROM rfcs")
        rows = cursor.fetchall()

        if not rows:
            print("[-] No RFCs found in database. Run 'fetch' first.")
            return

        total_chunks = 0
        for row in rows:
            rfc_id = row["rfc_id"]
            doc_path = row["doc_path"]
            try:
                with open(doc_path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                num_str = "".join(ch for ch in str(rfc_id) if ch.isdigit())
                rfc_num = int(num_str) if num_str else None
                fragments = RFCChunker.chunk_document_for_terminator(
                    text, sentences_per_chunk=args.sentences, rfc_num=rfc_num
                )
                saved = db.save_fragments(rfc_id, fragments)
                total_chunks += saved
                print(f"[+] {rfc_id}: Generated and saved {saved} micro-inspiration fragments.")
            except Exception as e:
                print(f"[!] Error chunking {rfc_id}: {e}")

        print(f"[*] Successfully saved {total_chunks} total micro-inspiration fragments.")
    finally:
        db.close()


def cmd_generate(args):
    db = Database(args.db)
    try:
        unprocessed = db.get_unprocessed_fragments(limit=args.limit)

        if not unprocessed:
            print("[-] No unprocessed fragments. Run 'chunk' first.")
            return

        print(f"[+] Generating novel candidate probes from {len(unprocessed)} fragments using {args.model} (fusion={args.fusion})...")
        generator = ProbeGenerator(preferred_model=args.model, use_fusion=args.fusion, db=db)

        total_probes = 0
        for frag in unprocessed:
            frag_id = frag["fragment_id"]
            rfc_id = frag["rfc_id"]
            content = frag["content"]

            print(f"\n[*] Fragment [{rfc_id} #{frag_id}]: {content[:80]}...")
            probes = generator.generate_candidate_probes(content, fragment_id=frag_id)
            for p in probes:
                print(f"    -> [Probe #{p.get('probe_id')}] (Clean: {p['is_clean']}) {p['rationale']}")
                total_probes += 1

        print(f"\n[+] Generated and saved {total_probes} candidate probes.")
    finally:
        db.close()


def cmd_permute(args):
    db = Database(args.db)
    try:
        cursor = db.conn.cursor()
        cursor.execute(
            "SELECT probe_id, fragment_id, rationale, raw_request, is_clean FROM probes WHERE source_type IN ('llm', 'fusion') LIMIT ?",
            (args.limit,),
        )
        rows = [dict(r) for r in cursor.fetchall()]

        if not rows:
            print("[-] No base probes to permute. Run 'generate' first.")
            return

        permutator = VectorPermutator(db=db)
        total_permuted = 0
        for row in rows:
            variants = permutator.permute_probe(row, max_variants=args.variants)
            for v in variants:
                print(f"[+] Permutation #{v.get('probe_id')}: {v['rationale']}")
                total_permuted += 1

        print(f"[*] Generated {total_permuted} permuted probe variants.")
    finally:
        db.close()


def cmd_evaluate(args):
    """Evaluates pending probes with active host network containment."""
    with HostContainmentManager():
        return _cmd_evaluate_impl(args)


def _cmd_evaluate_impl(args):
    db = Database(args.db)
    try:
        pending = db.get_pending_probes(target_host=args.target, limit=args.limit)

        if not pending:
            print(f"[-] No pending probes for target {args.target}. Generate probes first or check test history.")
            return

        harness = DeterministicHarness(
            host=args.target,
            port=args.port,
            use_tls=args.tls,
            timeout=args.timeout,
            db=db,
        )

        print(f"[+] Starting deterministic evaluation of {len(pending)} probes against {args.target}:{args.port} (TLS={args.tls})...")

        vulnerable_count = 0
        concurrency = getattr(args, "concurrency", 4)
        if concurrency > 1 and len(pending) > 1:
            print(f"[*] Multithreaded evaluation active: {concurrency} threads (bounded by semaphore)")
            probes_list = [dict(r) for r in pending]
            results = harness.evaluate_batch_concurrent(probes_list, max_concurrency=concurrency)
            for (is_vuln, desync_class, details, meta) in results:
                if is_vuln:
                    vulnerable_count += 1
                    print(f"    [!] BREAKTHROUGH FINDING: {details} ({desync_class})")
                else:
                    if meta.get("anomalies"):
                        for anom in meta["anomalies"]:
                            print(f"    [~] ANOMALY DETECTED: {anom['type']} - {anom['description']}")
        else:
            for row in pending:
                probe_dict = dict(row)
                p_id = probe_dict["probe_id"]
                print(f"\n[*] Evaluating Probe #{p_id}: {probe_dict['rationale'][:70]}...")

                is_vuln, desync_class, details, meta = harness.run_evaluation(probe_dict)
                if is_vuln:
                    print(f"    [!] BREAKTHROUGH FINDING: {details}")
                    print(f"    [!] Attack Class: {desync_class}")
                    vulnerable_count += 1
                else:
                    print(f"    [-] Result: {details}")

                if meta.get("anomalies"):
                    for anom in meta["anomalies"]:
                        print(f"    [~] ANOMALY DETECTED: {anom['type']} - {anom['description']}")

        print(f"\n[*] Evaluation complete: {vulnerable_count} breakthroughs out of {len(pending)} evaluated.")
    finally:
        db.close()


def cmd_weaponize(args):
    db = Database(args.db)
    try:
        weaponizer = RQPWeaponizer(
            host=args.target,
            port=args.port,
            use_tls=args.tls,
            db=db,
        )

        # Use specified raw trigger or search database for confirmed findings
        sample_trigger = (
            "POST / HTTP/1.1\r\n"
            "Host: target.local\r\n"
            "Content-Type: multipart/byteranges; boundary=BOUND\r\n"
            "Content-Length: 120\r\n\r\n"
            "$PAYLOAD"
        )

        print(f"[+] Launching Autonomous RQP with Dangling-Byte Technique on {args.target}:{args.port}...")
        is_stolen, reason, evidence = weaponizer.test_dangling_byte_rqp(sample_trigger)
        if is_stolen:
            print(f"\n[!] WEAPONIZATION SUCCESS: {reason}")
        else:
            print(f"\n[-] Weaponization outcome: {reason}")
    finally:
        db.close()


def cmd_cascade(args):
    db = Database(args.db)
    try:
        confirmed = db.get_confirmed_findings()

        if not confirmed:
            print("[-] No confirmed vulnerable findings yet. Run 'evaluate' to surface discoveries first.")
            # Provide a synthetic finding demo to verify cascade logic if requested
            if getattr(args, "demo", False):
                print("[*] Running Cascade Extrapolation demo on Kettle's RFC 2616 multipart/byteranges finding...")
                confirmed = [{
                    "eval_id": 1,
                    "rationale": "RFC 2616 §19.2 response rule applied in request",
                    "rfc_fragment": "The one exception is the 'multipart/byteranges' type when it appears in a 206 response.",
                    "details": "Status shift 200 -> 405. Marker reflected in victim stream.",
                    "raw_evidence": "HTTP/1.1 200 OK\r\n\r\nTrigger Accepted\n--- POLLUTED ---\nHTTP/1.1 405 Method Not Allowed",
                }]
            else:
                return

        cascade_engine = DiscoveryCascade(preferred_model=args.model, use_fusion=args.fusion, db=db)
        for finding in confirmed:
            f_dict = dict(finding)
            print(f"\n[+] Extrapolating finding #{f_dict.get('eval_id')}: {f_dict.get('details')}")
            result = cascade_engine.cascade_from_finding(f_dict, eval_id=f_dict.get("eval_id"))
            if result:
                print(f"    [Cascade Category]: {result['category']}")
                print(f"    [Hypothesis]: {result['hypothesis']}")
                print(f"    [New Probes Synthesized]: {len(result['suggested_probes'])}")
    finally:
        db.close()


def cmd_lab(args):
    server = TestLabServer(
        host=args.host,
        port=args.port,
        auth_boundary_patched=bool(getattr(args, "patched", False)),
    )
    server.start()
    try:
        print("[*] Test Lab Server is active. Press Ctrl+C to stop.")
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        server.stop()


def cmd_auto(args):
    """Continuous research loop: Ingest -> Chunk -> Generate -> Permute -> Evaluate -> Cascade."""
    print("=" * 70)
    print("  HTTP TERMINATOR: AUTONOMOUS PROTOCOL RESEARCH CASCADE ENGINE")
    print("  Model: Google Gemma 2 / Local ModelFusion (Zero-Cost 24/7 Mode)")
    print("=" * 70)

    # 1. Fetch
    cmd_fetch(args)

    # 2. Chunk
    cmd_chunk(args)

    # 3. Generate
    cmd_generate(args)

    # 4. Permute
    cmd_permute(args)

    # 5. Start Lab Server in background if targeting local lab
    lab_server = None
    if args.target == "127.0.0.1" and args.port == 8080:
        lab_server = TestLabServer(host="127.0.0.1", port=8080)
        lab_server.start()
        time.sleep(0.5)

    with HostContainmentManager():
        try:
            # 6. Evaluate
            cmd_evaluate(args)

            # 7. Weaponize
            cmd_weaponize(args)

            # 8. Cascade
            cmd_cascade(args)

            # 9. Caldera Auto-Sync (Default)
            try:
                from engine.caldera_bridge import CalderaBridge
                bridge = CalderaBridge(db_path=args.db)
                c_res = bridge.export_plugin(output_dir="caldera_export")
                bridge.export_plugin(output_dir=".")
                print(f"\n[+] Caldera Auto-Sync [Default]: {c_res['abilities_count']} abilities and {c_res['adversaries_count']} adversaries updated.")
            except Exception as e:
                print(f"[-] Caldera Auto-Sync notice: {e}")

            # 10. Dream-RSI Auto-Optimization (Default)
            if not getattr(args, "no_dream_rsi", False):
                try:
                    print(f"\n[*] Dream-RSI Auto-Optimization [Default]: Evolving off-policy exploration trajectories...")
                    cmd_dream(args)
                except Exception as e:
                    print(f"[-] Dream-RSI Auto-Optimization notice: {e}")

        finally:
            if lab_server:
                lab_server.stop()


def cmd_hunt(args):
    """Continuously fetches RFCs and evaluates until flaws are discovered."""
    from continuous_scanner import ContinuousFlawHunter

    hunter = ContinuousFlawHunter(
        target_host=args.target,
        target_port=args.port,
        use_tls=args.tls,
        preferred_model=args.model,
        use_fusion=args.fusion,
        db_path=args.db,
    )
    flaws = hunter.run_until_flaw(
        max_rfcs=args.max_rfcs,
        fragments_per_rfc=args.fragments,
        permutations_per_probe=args.variants,
        stop_on_first_flaw=not args.keep_going,
    )
    print(f"\n[*] Hunt complete. Total flaws/anomalies found: {len(flaws)}")

    # Caldera Auto-Sync (Default)
    try:
        from engine.caldera_bridge import CalderaBridge
        bridge = CalderaBridge(db_path=args.db)
        c_res = bridge.export_plugin(output_dir="caldera_export")
        bridge.export_plugin(output_dir=".")
        print(f"[+] Caldera Auto-Sync [Default]: {c_res['abilities_count']} abilities and {c_res['adversaries_count']} adversaries updated.")
    except Exception as e:
        pass

    # Dream-RSI Auto-Optimization (Default)
    if not getattr(args, "no_dream_rsi", False):
        try:
            print(f"\n[*] Dream-RSI Auto-Optimization [Default]: Evolving off-policy exploration trajectories...")
            cmd_dream(args)
        except Exception:
            pass


def cmd_mcp(args):
    """Runs the HTTP Terminator MCP Server over stdio, Streamable HTTP (/http), or Legacy SSE (/sse)."""
    from mcp_server import MCPHttpServer, TerminatorMCPServer
    transport = getattr(args, "transport", "stdio") or "stdio"
    with TerminatorMCPServer(db_path=args.db) as server:
        if transport == "stdio":
            server.run_stdio()
        else:
            http_srv = MCPHttpServer(
                server,
                host=getattr(args, "mcp_host", "127.0.0.1") or "127.0.0.1",
                port=int(getattr(args, "mcp_port", 8790) or 8790),
                bearer_token=getattr(args, "mcp_token", None),
            )
            http_srv.serve_forever()


def cmd_ruler(args):
    """Measures front-end transformations using backend header length limits (James Kettle technique)."""
    from protocol_ruler import ProtocolRuler
    use_tls = bool(args.tls or (args.port == 443))
    ruler = ProtocolRuler(
        host=args.target,
        port=args.port,
        use_tls=use_tls,
        timeout=args.timeout,
        verbose=args.verbose,
        debug=args.debug,
    )
    custom = []
    if getattr(args, "sequence", None):
        seq_str = args.sequence
        if seq_str.startswith("\\x"):
            seq_bytes = bytes.fromhex(seq_str.replace("\\x", ""))
        else:
            try:
                seq_bytes = bytes.fromhex(seq_str)
            except ValueError:
                seq_bytes = seq_str.encode("latin-1")
        custom.append((getattr(args, "name", "Custom Probe"), seq_bytes, f"User-supplied test sequence: {seq_str}"))

    ruler.run_comprehensive_audit(custom_sequences=custom, max_size=args.max_size)


def cmd_dream(args):
    """Executes offline Dream-RSI policy evolution over accumulated database trajectories."""
    from engine.dream_world_model import ProtocolWorldModel
    from engine.dream_rsi_optimizer import DreamRSIOptimizer
    from engine.dream_policy_store import DreamPolicyStore

    db_path = getattr(args, "db", "terminator.db")
    target_host = getattr(args, "target", "127.0.0.1")
    target_port = getattr(args, "port", 5006)
    export_path = getattr(args, "export", "data/dream_policies.json")
    generations = getattr(args, "generations", 2)
    rollouts = getattr(args, "rollouts", 200)

    print(f"[*] Initializing Dream-RSI World Model from {db_path}...")
    model = ProtocolWorldModel(target_host=target_host, target_port=target_port)
    loaded = model.ingest_history_from_db(db_path)
    print(f"[+] Loaded {loaded} execution trajectories into offline World Model.")

    optimizer = DreamRSIOptimizer(model)
    store = DreamPolicyStore(storage_path=export_path)

    print(f"[*] Executing {generations} generations of off-policy dreaming ({rollouts} rollouts each)...")
    for g in range(generations):
        evolved = optimizer.evolve_policy_generation(rollouts_per_candidate=rollouts)
        store.save_policy(evolved)
        gain_str = f"+{evolved.rsi_gain * 100:.1f}%" if evolved.rsi_gain > 0 else "0.0%"
        print(f"  [Gen {evolved.generation}] Fitness: {evolved.fitness_score:.2f} | RSI Gain: {gain_str} | Yield: {evolved.simulated_yield:.1%}")

    summary = store.export_summary()
    print(f"\n[+] Dream-RSI Optimization Complete. Policies saved to {export_path}.")
    print(f"    Total Cumulative Gain: {summary.get('cumulative_rsi_gain_pct', 0.0)}%")
    print(f"    Dominant Mutators: {summary.get('dominant_mutators', [])}")


def cmd_caldera(args):
    """Exports or pushes findings to Caldera adversary emulation platform."""
    from engine.caldera_bridge import CalderaBridge

    bridge = CalderaBridge(db_path=args.db)
    if args.export:
        print(f"[*] Exporting Caldera plugin to {args.export}...")
        res = bridge.export_plugin(output_dir=args.export)
        print(f"[+] Caldera plugin successfully exported to {res['plugin_path']}:")
        print(f"    Abilities generated: {res['abilities_count']}")
        print(f"    Adversaries generated: {res['adversaries_count']}")
        print(f"    Custom non-MITRE tactics: {', '.join(res['tactics'])}")
    elif args.push:
        if not args.api_key:
            print("[!] Error: --api-key is required when using --push")
            sys.exit(1)
        print(f"[*] Pushing abilities to Caldera at {args.push}...")
        findings = bridge.fetch_confirmed_findings_from_db()
        abilities = [bridge.generate_ability(f) for f in findings]
        adversary = bridge.generate_adversary(abilities) if abilities else None
        res = bridge.push_to_caldera(args.push, args.api_key, abilities=abilities, adversary=adversary)
        print(f"[+] Caldera API Push Result: {res['pushed_abilities']} abilities, {res['pushed_adversaries']} adversaries pushed.")
        if res["errors"]:
            print(f"[!] Warnings/Errors encountered during API push: {res['errors']}")
    else:
        # Default: export to ./caldera_export
        print("[*] No action specified. Exporting to default directory: ./caldera_export...")
        res = bridge.export_plugin(output_dir="caldera_export")
        print(f"[+] Caldera plugin successfully exported to {res['plugin_path']} ({res['abilities_count']} abilities).")


def cmd_build(args):
    """Executes the unified 'Build All' pipeline."""
    from build_all import run_full_build
    success = run_full_build(skip_tests=args.skip_tests)
    if not success:
        sys.exit(1)


def cmd_mantis(args):
    """Execute Google Mantis (Module 20) with mandatory ModelFusion & Abliterated model."""
    from engine.mantis_integrator import DEFAULT_ABLITERATED_MODEL, MantisIntegrator

    args.fusion = True
    args.abliteration = True
    preferred_model = DEFAULT_ABLITERATED_MODEL
    if getattr(args, "model", None) and "obliterated" in str(args.model).lower():
        preferred_model = args.model
    args.model = preferred_model

    target = getattr(args, "repo", None) or getattr(args, "path", None) or "."
    raw_depth = getattr(args, "depth", None)
    depth = 30 if raw_depth is None else int(raw_depth)
    mode = getattr(args, "mantis_mode", "full") or "full"
    reports_dir = getattr(args, "output_dir", None) or "reports"

    db = Database(args.db)
    try:
        integrator = MantisIntegrator(
            db=db,
            reports_dir=reports_dir,
            use_fusion=True,
            preferred_model=preferred_model,
            sec_model=getattr(args, "sec_model", None),
        )
        res = integrator.run_scan(target_path=str(target), depth=depth, mode=mode)
    finally:
        db.close()
    print(f"\n[+] Google Mantis Scan Complete: target={res['target_path']} depth={depth} mode={mode}")
    print(f"    Fusion Enabled: {res['fusion_enabled']} | Abliterated Model: {res['abliterated_model']}")
    print(f"    Total Findings: {res['total_findings']} | Reproduced: {res['reproduced_count']} | Patched Verified: {res['patched_verified_count']}")
    print(f"    SARIF Report  : {res['report_files'].get('sarif')}")


def _parse_csv_list(raw: Optional[str]) -> Optional[List[str]]:
    if not raw:
        return None
    items = [p.strip() for p in str(raw).split(",") if p.strip()]
    return items or None


def cmd_artex(args):
    """Execute BaaRai/ARTEX Dual-Graph & Durable Attack Chaining Engine (Module 17)."""
    from datetime import datetime, timezone
    from pathlib import Path as _Path
    import secrets as _secrets
    from engine.approval_gate import ApprovalGate
    from engine.artex_bridge import ArtexProxyConfig, TrafficCaptureSession
    from engine.cli_render import render_json, render_poe_summary
    from engine.dual_graph_engine import DualGraphAttackEngine, NoiseGovernor
    from engine.safe_network_validator import (
        is_explicit_loopback_host,
        parse_host_and_port,
        validate_and_authorize_target,
    )
    from engine.session_loader import (
        import_har_file,
        import_openapi_spec,
        load_auth_profiles,
        load_scope_file,
    )

    raw_host = getattr(args, "host", None) or getattr(args, "target", None) or "127.0.0.1"
    raw_port = int(getattr(args, "port", 8080) or 8080)
    raw_tls = getattr(args, "tls", None)
    as_json = bool(getattr(args, "as_json", False))
    authorized = bool(getattr(args, "authorized", False))
    t_host, t_port, inferred_tls = parse_host_and_port(
        raw_host,
        default_port=raw_port,
        use_tls=bool(raw_tls) if raw_tls is not None else None,
    )
    use_tls = bool(raw_tls) or ("://" in str(raw_host) and inferred_tls)
    ok, reason = validate_and_authorize_target(t_host, authorized=authorized)
    if not ok:
        print(f"[!] Target authorization error for {raw_host}: {reason}", file=(sys.stderr if as_json else sys.stdout))
        sys.exit(1)

    artex_multiturn = bool(getattr(args, "artex_multiturn", False))
    artex_intent_turns = int(getattr(args, "artex_intent_turns", 0) or 0)
    artex_intent_tokens = int(getattr(args, "artex_intent_tokens", 0) or 0)
    artex_budget_turns = int(getattr(args, "artex_budget_turns", 0) or 0)
    if artex_intent_turns < 0 or artex_intent_tokens < 0 or artex_budget_turns < 0:
        print(
            "[!] ARTEX budget/turn parameters must be non-negative (>= 0).",
            file=(sys.stderr if as_json else sys.stdout),
        )
        sys.exit(1)

    reports_dir = getattr(args, "output_dir", None) or "reports"
    rounds = max(1, int(getattr(args, "artex_rounds", 1) or 1))
    workers = max(1, int(getattr(args, "artex_workers", 3) or 3))
    strict_poe = bool(getattr(args, "strict_poe", False))
    approval_mode = getattr(args, "approval_mode", "policy") or "policy"
    approval_rules = getattr(args, "approval_rules", None)
    scope_file = getattr(args, "scope_file", None)
    auth_profile = getattr(args, "auth_profile", None)
    import_har = getattr(args, "import_har", None)
    import_openapi = getattr(args, "import_openapi", None)
    embedded_proxy = bool(getattr(args, "embedded_proxy", False))
    embedded_proxy_port = int(getattr(args, "embedded_proxy_port", 0) or 0)
    export_advisory = bool(getattr(args, "export_advisory", False))
    export_csv = bool(getattr(args, "export_csv", False))
    noise_profile = getattr(args, "artex_noise_profile", None)
    llm_profiles = _parse_csv_list(getattr(args, "artex_llm_profiles", None))

    shared_task_id = f"ARTEX-TASK-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{_secrets.token_hex(3)}"
    shared_noise = NoiseGovernor(profile=noise_profile)

    proxy_cfg = ArtexProxyConfig.from_env_or_args(
        proxy_url=getattr(args, "artex_proxy", None),
        ca_cert_path=getattr(args, "artex_ca_cert", None),
        authorized=authorized,
    )

    db = Database(args.db)
    embedded_mitm = None
    arbiter = None
    try:
        if getattr(args, "fusion", True) and os.environ.get("RFCHUNT_OFFLINE") != "1":
            try:
                from fusion_engine import FusionArbiter
                arbiter = FusionArbiter(
                    db=db,
                    preferred_model=getattr(args, "model", None),
                    sec_model=getattr(args, "sec_model", None),
                    quiet=as_json,
                )
            except Exception:
                arbiter = None
        traffic_session = TrafficCaptureSession(db=db, task_id=shared_task_id, proxy_config=proxy_cfg)
        approval_gate = (
            ApprovalGate.from_rules_file(approval_rules, mode=approval_mode, db=db, task_id=shared_task_id)
            if approval_rules
            else ApprovalGate(mode=approval_mode, db=db, task_id=shared_task_id)
        )
        loaded_scope = load_scope_file(scope_file) if scope_file else {"allow_hosts": [], "deny_hosts": [], "deny_routes": []}
        scope_hosts_set = set(loaded_scope.get("allow_hosts") or []) or None
        loaded_auth_profiles = load_auth_profiles(auth_profile) if auth_profile else {}

        if embedded_proxy:
            from engine.local_mitm_proxy import LocalRecordingMITMProxy
            embedded_mitm = LocalRecordingMITMProxy(
                host="127.0.0.1",
                port=embedded_proxy_port,
                db=db,
                task_id=shared_task_id,
                traffic_session=traffic_session,
                noise_governor=shared_noise,
                authorized=authorized or is_explicit_loopback_host(t_host),
            )
            embedded_mitm.start()
            proxy_cfg = ArtexProxyConfig(
                proxy_url=embedded_mitm.proxy_url,
                ca_cert_path=embedded_mitm.ca_cert_path,
                enabled=True,
            )
            traffic_session.proxy_config = proxy_cfg

        artex_live_val = getattr(args, "artex_live", None)
        if getattr(args, "no_artex_live", False):
            artex_live_val = False
        _is_loopback = is_explicit_loopback_host(t_host)
        _enable_live = False
        if artex_live_val is True:
            _enable_live = bool(authorized or _is_loopback)
        elif artex_live_val is None and (authorized or _is_loopback):
            import socket as _sock
            try:
                with _sock.create_connection((t_host, t_port), timeout=1.0):
                    _enable_live = True
            except OSError:
                _enable_live = False

        live_executor_fn = None
        live_registry = None
        if _enable_live:
            from engine.live_executors import LiveWorkerExecutorRegistry
            live_registry = LiveWorkerExecutorRegistry(
                host=t_host,
                port=t_port,
                use_tls=use_tls,
                authorized=bool(authorized or _is_loopback),
                traffic_session=traffic_session,
                approval_gate=approval_gate,
                noise_governor=shared_noise,
                auth_profiles=loaded_auth_profiles,
                arbiter=arbiter,
            )
            live_executor_fn = live_registry.as_executor_fn()

        engine = DualGraphAttackEngine(
            db=db,
            reports_dir=reports_dir,
            task_id=shared_task_id,
            scope_hosts=scope_hosts_set,
            noise_profile=noise_profile,
            max_task_turns=artex_budget_turns,
            max_intent_tokens=artex_intent_tokens,
            max_intent_turns=artex_intent_turns,
            llm_profile_ids=llm_profiles,
            llm_rotate=bool(getattr(args, "artex_llm_rotate", False)),
            proxy_config=proxy_cfg,
            traffic_session=traffic_session,
            workers=workers,
            arbiter=arbiter,
            strict_poe=strict_poe,
            approval_gate=approval_gate,
            default_executor_fn=live_executor_fn,
        )
        engine.noise_governor = shared_noise
        engine.worker.noise_governor = shared_noise
        if live_registry is not None:
            live_registry.budget_ledger = engine.budget_ledger
            live_registry.trace_store = engine.trace_store
            live_registry.boundary = engine.boundary
            live_registry.asset_graph = engine.asset_graph
            if artex_multiturn:
                mt_turns = artex_intent_turns if artex_intent_turns > 0 else None
                engine.default_executor_fn = live_registry.as_multiturn_executor_fn(
                    max_turns=mt_turns,
                    budget_ledger=engine.budget_ledger,
                    trace_store=engine.trace_store,
                    boundary=engine.boundary,
                    asset_graph=engine.asset_graph,
                )
        for deny_h in loaded_scope.get("deny_hosts") or []:
            engine.asset_graph.deny_hosts.add(str(deny_h).lower())
        for deny_r in loaded_scope.get("deny_routes") or []:
            engine.asset_graph.deny_routes.append(str(deny_r))

        if import_openapi:
            import_openapi_spec(
                import_openapi,
                asset_graph=engine.asset_graph,
                default_host=t_host,
                default_port=t_port,
                host=t_host,
                port=t_port,
            )
        if import_har:
            har_res = import_har_file(import_har, asset_graph=engine.asset_graph, traffic_session=traffic_session)
            if not loaded_auth_profiles and har_res.get("extracted_auth_headers"):
                from engine.session_loader import AuthProfile as _AP
                loaded_auth_profiles["har_session"] = _AP(
                    name="har_session",
                    role="end_user",
                    headers=dict(har_res["extracted_auth_headers"]),
                )
                if live_registry is not None:
                    live_registry.auth_profiles.update(loaded_auth_profiles)

        # Hydrate AI sinks & endpoints from DB before chaining
        ai_sinks = []
        try:
            cur = db.conn.cursor()
            cur.execute("SELECT DISTINCT file_path, model_or_api FROM ai_security_findings WHERE finding_type = 'unmetered_ai_endpoint'")
            for r in cur.fetchall():
                ai_sinks.append({"route": "/api/chat", "method": "POST", "model_provider": r["model_or_api"], "file_path": r["file_path"]})
        except Exception:
            pass
        if not ai_sinks:
            ai_sinks = [{"route": "/api/chat", "method": "POST", "model_provider": "local_ai", "file_path": "server.py"}]

        engine.ingest_target_infrastructure(host=t_host, port=t_port, endpoints=["/api/v1"], ai_sinks=ai_sinks)
        hydrated = engine.ingest_from_database(db)
        if sum(hydrated.values()) == 0:
            engine.register_wire_primitive(
                anomaly_id="RFC9112-CHUNK-DESYNC",
                description="HTTP/1.1 Framing Desync (Chunk Extension & Content-Length conflict)",
                anomaly_type="CL.TE_DESYNC",
            )

        _stdout_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
        with _stdout_ctx:
            res = engine.run_attack_chain_cycle(
                round_num=rounds,
                retest_existing=bool(getattr(args, "artex_retest", False)),
            )

            artex_url = getattr(args, "artex_url", None) or os.environ.get("ARTEX_API_URL")
            remote_res = None
            if artex_url:
                remote_res = engine.sync_with_headless_artex(
                    artex_url=artex_url,
                    token=getattr(args, "artex_token", None),
                    authorized=authorized,
                    llm_profile_ids=llm_profiles,
                    llm_rotate=bool(getattr(args, "artex_llm_rotate", False)) if llm_profiles else None,
                    wait_sse=bool(getattr(args, "artex_wait_sse", False)),
                )

        stored_chains = db.get_attack_chains(limit=50, task_id=shared_task_id) if hasattr(db, "get_attack_chains") else []
        traces_list = db.list_worker_traces(task_id=shared_task_id, limit=25) if hasattr(db, "list_worker_traces") else []

        extra_exports: Dict[str, Any] = {}
        if export_advisory or export_csv:
            from engine.advisory_exporter import AdvisoryExporter, _safe_filename
            out_dir = _Path(reports_dir)
            exporter = AdvisoryExporter(reports_dir=out_dir)
            if export_csv:
                csv_path = out_dir / "findings_and_chains.csv"
                exporter.export_findings_csv([], chains=stored_chains, output_path=csv_path)
                extra_exports["csv"] = str(csv_path)
            if export_advisory:
                adv_paths: List[str] = []
                for ch in stored_chains[:25]:
                    cid = str(ch.get("chain_id") or "CHAIN")
                    tid = ch.get("traffic_id")
                    trec = db.get_traffic_evidence(tid) if tid else None
                    rtests = db.get_chain_retests(chain_id=cid)
                    out_md = out_dir / f"advisory_{_safe_filename(cid)}.md"
                    exporter.export_ghsa_markdown(ch, traffic_record=trec, retests=rtests, output_path=out_md)
                    adv_paths.append(str(out_md))
                extra_exports["advisories"] = adv_paths

        if getattr(args, "as_json", False):
            render_json({"result": res, "hydrated": hydrated, "remote_artex": remote_res, "exports": extra_exports})
            return

        cov = res.get("coverage") or {}
        todo = res.get("todolist_summary") or {}
        print(f"\n[+] ARTEX Dual-Graph Attack Chaining Complete: target={t_host}:{t_port} rounds={rounds} workers={workers}")
        print(f"    DB Hydrated        : {hydrated}")
        print(f"    Assets / Coverage  : {res['total_assets']} assets ({cov.get('tested_assets', 0)}/{cov.get('total_in_scope_assets', 0)} = {cov.get('coverage_pct', 0.0)}%)")
        print(f"    Attack Chains      : {res['candidates_planned']} planned | {res['exploits_verified']} verified | Max Hops: {res.get('max_hop_count', 0)}")
        print(f"    Todolist / Traces  : {todo.get('completed_chains', 0)}/{todo.get('total_chains', 0)} chains complete | {res.get('worker_traces_count', 0)} worker traces | Goal Proven: {res.get('goal_proven', False)}")
        if proxy_cfg.enabled:
            print(f"    MITM Proxy         : {proxy_cfg.proxy_url}")
        if remote_res is not None:
            print(f"    Headless ARTEX API : {remote_res.get('status')} (task_id={remote_res.get('task_id')}, traffic_ingested={remote_res.get('traffic_ingested', 0)})")
        for rtype, rpath in (res.get("report_files") or {}).items():
            print(f"    Report ({rtype.upper():<7}) : {rpath}")
        if extra_exports.get("csv"):
            print(f"    CSV Export         : {extra_exports['csv']}")
        if extra_exports.get("advisories"):
            print(f"    GHSA Advisories    : {len(extra_exports['advisories'])} written")
        render_poe_summary(
            res.get("poe_breakdown") or {},
            coverage=cov,
            chains=stored_chains,
            traces=traces_list,
            plain=bool(getattr(args, "plain", False)),
        )
    except (PermissionError, ValueError) as exc:
        print(f"[!] ARTEX execution rejected: {exc}", file=(sys.stderr if as_json else sys.stdout))
        sys.exit(1)
    finally:
        if embedded_mitm is not None:
            try:
                embedded_mitm.stop()
            except Exception:
                pass
        if arbiter is not None and hasattr(arbiter, "close"):
            try:
                arbiter.close()
            except Exception:
                pass
        db.close()


def cmd_artex_loop(args):
    """Execute bounded multi-turn ArtexWorker tool loop via CLI."""
    args.artex_multiturn = True
    if getattr(args, "artex_live", None) is None and not bool(getattr(args, "no_artex_live", False)):
        args.artex_live = True
    return cmd_artex(args)


def cmd_scanner(args):
    """Execute opt-in external scanners (`httpx`, `katana`, `nuclei`) into AssetGraph & DualGraph."""
    from datetime import datetime, timezone
    import secrets as _secrets
    from engine.approval_gate import ApprovalGate
    from engine.cli_render import render_json, render_kv_panel, render_table
    from engine.dual_graph_engine import DualGraphAttackEngine, NoiseGovernor
    from engine.external_scanners import (
        DEFAULT_NUCLEI_TAGS,
        ExternalScannerConfig,
        _normalize_nuclei_tags,
        run_opt_in_external_discovery,
        run_opt_in_nuclei_scan,
    )
    from engine.safe_network_validator import (
        is_explicit_loopback_host,
        parse_host_and_port,
        validate_and_authorize_target,
    )
    from engine.session_loader import load_scope_file

    raw_host = getattr(args, "host", None) or getattr(args, "target", None) or "127.0.0.1"
    raw_port = getattr(args, "port", None)
    explicit_dests = getattr(args, "_explicit_cli_dests", set())
    if "port" in explicit_dests and raw_port is not None:
        eff_default_port = int(raw_port)
    elif str(raw_host).strip().lower().startswith("http://"):
        eff_default_port = 80
    elif raw_port is not None:
        eff_default_port = int(raw_port)
    else:
        eff_default_port = 443
    raw_tls = getattr(args, "tls", None)
    authorized = bool(getattr(args, "authorized", False))
    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    err_stream = sys.stderr if as_json else sys.stdout

    try:
        clean_host, resolved_port, resolved_tls = parse_host_and_port(
            raw_host,
            default_port=eff_default_port,
            use_tls=bool(raw_tls) if raw_tls is not None else None,
        )
        ok, reason = validate_and_authorize_target(clean_host, authorized=authorized)
        if not ok:
            raise PermissionError(reason)
    except (PermissionError, ValueError) as exc:
        print(f"[!] Target authorization error for {raw_host}: {exc}", file=err_stream)
        sys.exit(1)

    scanner_isolation = getattr(args, "scanner_isolation", "host") or "host"
    if scanner_isolation not in ("host", "docker"):
        print(
            f"[!] Unsupported --scanner-isolation value: {scanner_isolation!r}. Expected 'host' or 'docker'.",
            file=err_stream,
        )
        sys.exit(1)

    raw_tags = getattr(args, "nuclei_tags", None)
    try:
        norm_tags = _normalize_nuclei_tags(raw_tags) if raw_tags is not None else DEFAULT_NUCLEI_TAGS
    except (ValueError, PermissionError) as exc:
        print(f"[!] Invalid --nuclei-tags: {exc}", file=err_stream)
        sys.exit(1)

    enable_all = bool(getattr(args, "enable_external_scanners", False))
    hx = getattr(args, "httpx_scan", None)
    kt = getattr(args, "katana_scan", None)
    nc = getattr(args, "nuclei_scan", None)
    any_enabled = enable_all or bool(hx) or bool(kt) or bool(nc)

    fmt_host = f"[{clean_host}]" if ":" in clean_host and not clean_host.startswith("[") else clean_host
    target_url = f"{'https' if resolved_tls else 'http'}://{fmt_host}:{resolved_port}"

    if not any_enabled:
        disabled_payload = {
            "status": "disabled",
            "ok": False,
            "scans_run": 0,
            "target": target_url,
            "execution_mode": scanner_isolation,
            "discovery": {"status": "disabled", "ok": False, "endpoints": [], "ai_sinks": []},
            "nuclei": {"status": "disabled", "ok": False, "findings": [], "total_findings": 0},
        }
        if as_json:
            render_json(disabled_payload)
        else:
            render_kv_panel(
                "External Scanners (Opt-In Disabled)",
                {
                    "Status": "disabled (pass --enable-external-scanners or --httpx-scan/--katana-scan/--nuclei-scan)",
                    "Target": target_url,
                    "Isolation": scanner_isolation,
                    "Scans Run": 0,
                },
                plain=plain,
            )
        return

    if hx is None and kt is None and nc is None:
        run_httpx = run_katana = run_nuclei = True
    else:
        run_httpx = bool(hx) if hx is not None else enable_all
        run_katana = bool(kt) if kt is not None else enable_all
        run_nuclei = bool(nc) if nc is not None else enable_all

    try:
        cfg = ExternalScannerConfig(
            enabled=True,
            execution_mode=scanner_isolation,
            docker_image=getattr(args, "docker_image", None),
            docker_network=getattr(args, "docker_network", None),
            nuclei_tags=norm_tags,
        )
    except (ValueError, PermissionError) as exc:
        print(f"[!] Invalid external scanner configuration: {exc}", file=err_stream)
        sys.exit(1)

    reports_dir = getattr(args, "output_dir", None) or "reports"
    noise_profile = getattr(args, "artex_noise_profile", None)
    approval_mode = getattr(args, "approval_mode", "policy") or "policy"
    approval_rules = getattr(args, "approval_rules", None)
    scope_file = getattr(args, "scope_file", None)
    shared_task_id = f"SCAN-TASK-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{_secrets.token_hex(3)}"
    eff_auth = bool(authorized or is_explicit_loopback_host(clean_host))

    db = Database(args.db)
    try:
        gate = (
            ApprovalGate.from_rules_file(approval_rules, mode=approval_mode, db=db, task_id=shared_task_id)
            if approval_rules
            else ApprovalGate(mode=approval_mode, db=db, task_id=shared_task_id)
        )
        noise_gov = NoiseGovernor(profile=noise_profile)
        loaded_scope = load_scope_file(scope_file) if scope_file else {"allow_hosts": [], "deny_hosts": [], "deny_routes": []}
        scope_hosts_set = set(loaded_scope.get("allow_hosts") or []) or None

        engine = DualGraphAttackEngine(
            db=db,
            reports_dir=reports_dir,
            task_id=shared_task_id,
            scope_hosts=scope_hosts_set,
            noise_profile=noise_profile,
            approval_gate=gate,
        )
        for deny_h in loaded_scope.get("deny_hosts") or []:
            engine.asset_graph.deny_hosts.add(str(deny_h).lower())
        for deny_r in loaded_scope.get("deny_routes") or []:
            engine.asset_graph.deny_routes.append(str(deny_r))

        discovery_res: Dict[str, Any] = {
            "status": "disabled",
            "ok": False,
            "endpoints": [],
            "ai_sinks": [],
            "js_endpoints": [],
            "technologies": [],
            "assets_added": 0,
        }
        nuclei_res: Dict[str, Any] = {
            "status": "disabled",
            "ok": False,
            "tags": list(norm_tags),
            "findings": [],
            "total_findings": 0,
            "findings_ingested": 0,
        }

        _stdout_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
        with _stdout_ctx:
            from engine.external_scanners import resolve_external_scanner_tool_configs
            discovery_cfg, nuclei_cfg = resolve_external_scanner_tool_configs(
                cfg,
                run_httpx=run_httpx,
                run_katana=run_katana,
                run_nuclei=run_nuclei,
            )
            if run_httpx or run_katana:
                discovery_res = run_opt_in_external_discovery(
                    target_url,
                    config=discovery_cfg,
                    asset_graph=engine.asset_graph,
                    authorized=eff_auth,
                    approval_gate=gate,
                    noise_governor=noise_gov,
                    run_httpx=run_httpx,
                    run_katana=run_katana,
                )
            if run_nuclei:
                nuclei_res = run_opt_in_nuclei_scan(
                    target_url,
                    config=nuclei_cfg,
                    dual_graph_engine=engine,
                    authorized=eff_auth,
                    approval_gate=gate,
                    noise_governor=noise_gov,
                )

        scans_run = int(bool(run_httpx)) + int(bool(run_katana)) + int(bool(run_nuclei))
        payload = {
            "status": "completed",
            "ok": bool(discovery_res.get("ok") or nuclei_res.get("ok")),
            "scans_run": scans_run,
            "task_id": shared_task_id,
            "target": target_url,
            "execution_mode": scanner_isolation,
            "discovery": discovery_res,
            "nuclei": nuclei_res,
            "endpoints": list(discovery_res.get("endpoints") or []),
            "ai_sinks": list(discovery_res.get("ai_sinks") or []),
            "findings": list(nuclei_res.get("findings") or []),
        }
    except (PermissionError, ValueError) as exc:
        print(f"[!] External scanner execution rejected: {exc}", file=err_stream)
        sys.exit(1)
    finally:
        db.close()

    if as_json:
        render_json(payload)
        return

    render_kv_panel(
        "External Scanners Summary",
        {
            "Task ID": shared_task_id,
            "Target": target_url,
            "Isolation": scanner_isolation,
            "Scans Run": scans_run,
            "Endpoints": len(payload["endpoints"]),
            "AI Sinks": len(payload["ai_sinks"]),
            "Nuclei Findings": len(payload["findings"]),
        },
        plain=plain,
    )
    rows: List[List[Any]] = []
    for ep in payload["endpoints"]:
        rows.append(["endpoint", ep, "AssetGraph"])
    for nf in payload["findings"]:
        if isinstance(nf, dict):
            rows.append([nf.get("severity", "INFO"), nf.get("rule_id", ""), nf.get("file_path", "")])
    render_table("Discovered Surface & Findings", ["Kind/Severity", "Item", "Target"], rows, plain=plain)


def cmd_proxy(args):
    """Start the embedded pure-CLI recording HTTP/HTTPS MITM proxy (Pillar 2)."""
    import time as _time
    from engine.artex_bridge import TrafficCaptureSession
    from engine.cli_render import render_kv_panel
    from engine.dual_graph_engine import NoiseGovernor
    from engine.local_mitm_proxy import LocalRecordingMITMProxy, RewriteRule

    rewrite_rules = []
    for raw_rule in (getattr(args, "rewrite_rule", None) or []):
        # Format: name:header=value  (e.g. trace:X-RFCHunt=1)
        if ":" in raw_rule and "=" in raw_rule:
            rname, rest = raw_rule.split(":", 1)
            hname, hval = rest.split("=", 1)
            rewrite_rules.append(
                RewriteRule(rule_id=rname.strip(), phase="request", header_name=hname.strip(), header_value=hval.strip())
            )
        elif "=" in raw_rule:
            hname, hval = raw_rule.split("=", 1)
            rewrite_rules.append(
                RewriteRule(rule_id=f"set_{hname.strip()}", phase="request", header_name=hname.strip(), header_value=hval.strip())
            )

    db = Database(args.db)
    try:
        session = TrafficCaptureSession(db=db, task_id=getattr(args, "task_id", None) or "PROXY-SESSION")
        governor = NoiseGovernor(profile=getattr(args, "noise_profile", None))
        raw_port = getattr(args, "port", None)
        bind_port = 8788 if raw_port is None else int(raw_port)
        proxy = LocalRecordingMITMProxy(
            host=getattr(args, "host", "127.0.0.1") or "127.0.0.1",
            port=bind_port,
            keys_dir=getattr(args, "ca_dir", "keys") or "keys",
            traffic_session=session,
            noise_governor=governor,
            rewrite_rules=rewrite_rules,
            authorized=bool(getattr(args, "authorized", False)),
        )
        proxy.start()
        try:
            info = {
                "Proxy URL": proxy.proxy_url,
                "CA Cert": proxy.ca_cert_path,
                "DB": args.db,
                "Noise Profile": governor.profile,
                "Authorized Remote": bool(getattr(args, "authorized", False)),
                "Rewrite Rules": len(rewrite_rules),
            }
            render_kv_panel(
                "RFCHunt Embedded Recording MITM Proxy",
                info,
                as_json=bool(getattr(args, "as_json", False)),
                plain=bool(getattr(args, "plain", False)),
            )
            duration = getattr(args, "duration", None)
            if duration is not None and float(duration) >= 0:
                _time.sleep(float(duration))
            else:
                try:
                    while True:
                        _time.sleep(0.5)
                except KeyboardInterrupt:
                    pass
        finally:
            proxy.stop()
    finally:
        db.close()


def cmd_chains(args):
    """Query and display persisted ARTEX attack chains from the SQLite database."""
    from engine.cli_render import render_chains

    db = Database(args.db)
    try:
        min_poe = int(getattr(args, "min_poe", 0) or 0)
        verified_only = bool(getattr(args, "verified_only", False))
        chains = db.get_attack_chains(
            limit=int(getattr(args, "limit", 50) or 50),
            task_id=getattr(args, "task_id", None),
            min_poe=min_poe if min_poe > 0 else None,
            verified_only=verified_only,
        )
        render_chains(
            chains,
            as_json=bool(getattr(args, "as_json", False)),
            plain=bool(getattr(args, "plain", False)),
        )
    finally:
        db.close()


def cmd_traces(args):
    """Search and inspect persisted ARTEX shared worker traces."""
    from engine.cli_render import render_traces

    db = Database(args.db)
    try:
        traces = db.list_worker_traces(
            task_id=getattr(args, "task_id", None),
            worker_id=getattr(args, "worker_id", None),
            query=getattr(args, "query", None),
            limit=int(getattr(args, "limit", 100) or 100),
        )
        render_traces(
            traces,
            as_json=bool(getattr(args, "as_json", False)),
            plain=bool(getattr(args, "plain", False)),
        )
    finally:
        db.close()


def cmd_coverage(args):
    """Compute and print the ARTEX Asset Coverage Ledger from persisted graphs."""
    from engine.cli_render import render_coverage
    from engine.dual_graph_engine import DualGraphAttackEngine

    db = Database(args.db)
    try:
        target_task_id = getattr(args, "task_id", None)
        # Use db=None so hydrating persisted graph nodes does not re-write every node back to SQLite
        engine = DualGraphAttackEngine(db=None, task_id=target_task_id)
        # Hydrate persisted asset & exploration nodes + anchors from DB
        for n in db.get_dual_graph_nodes():
            gtype = n.get("graph_type")
            nid = n.get("node_id")
            attrs = n.get("attributes") or {}
            if gtype == "ASSET":
                engine.asset_graph.add_asset(nid, n.get("node_type", "ENDPOINT"), n.get("label", nid), attrs)
            elif gtype == "EXPLORATION":
                node_task_id = attrs.get("task_id")
                if target_task_id and node_task_id is not None and node_task_id != target_task_id:
                    continue
                engine.exploration_graph.add_intent(
                    nid,
                    n.get("node_type", "FACT"),
                    n.get("label", nid),
                    anchored_asset_id=attrs.get("anchored_asset"),
                    attributes=attrs,
                    status=attrs.get("status", "PENDING"),
                )
        for anc in db.get_exploration_anchors(task_id=target_task_id):
            engine.exploration_graph.anchor_asset(anc["node_id"], anc["asset_id"])
        cov = engine.compute_coverage_ledger()
        render_coverage(
            cov,
            as_json=bool(getattr(args, "as_json", False)),
            plain=bool(getattr(args, "plain", False)),
        )
    finally:
        db.close()


def cmd_retest(args):
    """Replay persisted attack chains and record FIXED / STILL_REPRODUCIBLE / CANNOT_CONFIRM verdicts."""
    from engine.artex_bridge import TrafficCaptureSession
    from engine.cli_render import render_retest_results
    from engine.dual_graph_engine import ArtexRetester
    from engine.safe_network_validator import is_explicit_loopback_host, validate_and_authorize_target

    target_host = getattr(args, "host", None)
    target_port = getattr(args, "port", None)
    use_tls = getattr(args, "tls", None)
    authorized = bool(getattr(args, "authorized", False))
    live = bool(getattr(args, "live", False))

    if target_host:
        ok, reason = validate_and_authorize_target(target_host, authorized=authorized)
        if not ok:
            print(f"[!] Target authorization error for {target_host}: {reason}")
            sys.exit(1)
        live = True
        if is_explicit_loopback_host(target_host):
            authorized = True

    db = Database(args.db)
    try:
        session = TrafficCaptureSession(db=db, task_id=getattr(args, "task_id", None) or "RETEST")
        retester = ArtexRetester(db=db, traffic_session=session)
        chain_id = getattr(args, "chain_id", None)
        task_id_filter = getattr(args, "task_id", None)
        if chain_id:
            found = db.get_attack_chain(str(chain_id), task_id=task_id_filter)
            if found is None:
                print(f"[!] Attack chain '{chain_id}' not found.", file=sys.stderr)
                sys.exit(1)
            chains = [found]
        else:
            chains = db.get_attack_chains(
                limit=int(getattr(args, "limit", 50) or 50),
                task_id=task_id_filter,
            )
            if not getattr(args, "all_chains", False):
                chains = chains[:10]

        results = []
        for ch in chains:
            verifier_fn = None
            if live and not ch.get("traffic_id") and target_host:
                from engine.live_executors import LiveWorkerExecutorRegistry
                reg = LiveWorkerExecutorRegistry(
                    host=target_host,
                    port=int(target_port or 80),
                    use_tls=bool(use_tls),
                    authorized=authorized,
                    traffic_session=session,
                )
                def _live_fallback_verifier(chain_obj, _reg=reg):
                    ok_v, ev, _, meta = _reg.execute_candidate_live({
                        "attack_type": chain_obj.get("attack_type", ""),
                        "target_route": chain_obj.get("target_endpoint") or "/",
                        "raw_probe": chain_obj.get("raw_payload") or "",
                    })
                    if ok_v:
                        return True, ev
                    tid = meta.get("traffic_id")
                    ex = session.get_exchange(tid) if tid else None
                    if ex is not None and ex.status_code >= 500:
                        return None, ev
                    if ex is not None and ex.status_code in (400, 401, 403, 404, 405, 422):
                        return False, ev
                    return None, ev
                verifier_fn = _live_fallback_verifier

            results.append(
                retester.retest_chain(
                    ch,
                    verifier_fn=verifier_fn,
                    live=live,
                    authorized=authorized,
                    target_host=target_host,
                    target_port=int(target_port) if target_port is not None else None,
                    use_tls=use_tls,
                )
            )
        render_retest_results(
            results,
            as_json=bool(getattr(args, "as_json", False)),
            plain=bool(getattr(args, "plain", False)),
        )
    finally:
        db.close()


def cmd_export_advisory(args):
    """Export GHSA-ready Markdown advisories and/or formula-safe CSV from persisted findings."""
    from pathlib import Path as _Path
    from engine.advisory_exporter import AdvisoryExporter, _safe_filename
    from engine.cli_render import render_kv_panel

    out_dir = _Path(getattr(args, "out", None) or "reports")
    db = Database(args.db)
    try:
        exporter = AdvisoryExporter(reports_dir=out_dir)
        chain_id = getattr(args, "chain_id", None)
        task_id_filter = getattr(args, "task_id", None)
        if chain_id:
            found = db.get_attack_chain(str(chain_id), task_id=task_id_filter)
            if found is None:
                print(f"[!] Attack chain '{chain_id}' not found.", file=sys.stderr)
                sys.exit(1)
            chains = [found]
        else:
            chains = db.get_attack_chains(
                limit=int(getattr(args, "limit", 50) or 50),
                task_id=task_id_filter,
            )

        written_md: List[str] = []
        for ch in chains:
            cid = str(ch.get("chain_id") or "CHAIN")
            tid = ch.get("traffic_id")
            trec = db.get_traffic_evidence(tid) if tid else None
            rtests = db.get_chain_retests(chain_id=cid)
            out_md = out_dir / f"advisory_{_safe_filename(cid)}.md"
            exporter.export_ghsa_markdown(ch, traffic_record=trec, retests=rtests, output_path=out_md)
            written_md.append(str(out_md))

        csv_out = None
        if getattr(args, "csv", False):
            findings = db.get_mantis_findings(limit=500) if hasattr(db, "get_mantis_findings") else []
            csv_path = out_dir / "findings_and_chains.csv"
            exporter.export_findings_csv(findings, chains=chains, output_path=csv_path)
            csv_out = str(csv_path)

        summary = {
            "Output Directory": str(out_dir),
            "Advisories Exported": len(written_md),
            "Files": written_md,
            "CSV Exported": csv_out or "disabled",
        }
        render_kv_panel(
            "RFCHunt Advisory Export",
            summary,
            as_json=bool(getattr(args, "as_json", False)),
            plain=bool(getattr(args, "plain", False)),
        )
    finally:
        db.close()


def cmd_archive(args):
    """Export or import AES-256-GCM encrypted task archives (*.rfca) with SHA-256 verification."""
    from engine.advisory_exporter import AdvisoryExporter
    from engine.cli_render import render_kv_panel
    from engine.secret_store import SecretBox

    key_file = getattr(args, "key_file", None)
    export_path = getattr(args, "export_path", None)
    import_path = getattr(args, "import_path", None)
    if not export_path and not import_path:
        print("[!] Specify either --export <file.rfca> or --import <file.rfca>.")
        sys.exit(1)

    if export_path:
        db = Database(args.db, secret_key_path=key_file)
        try:
            box = db.secret_box or SecretBox.from_env_or_keyfile(key_path=key_file, create_if_missing=True)
            res = AdvisoryExporter().export_task_archive(
                db,
                export_path,
                task_id=getattr(args, "task_id", None),
                secret_box=box,
            )
            render_kv_panel(
                "RFCHunt Encrypted Archive Export",
                res,
                as_json=bool(getattr(args, "as_json", False)),
                plain=bool(getattr(args, "plain", False)),
            )
        finally:
            db.close()
    else:
        box = SecretBox.from_env_or_keyfile(key_path=key_file, create_if_missing=False)
        res = AdvisoryExporter.import_task_archive(import_path, secret_box=box)
        summary = {
            "Archive": import_path,
            "Schema": res["schema"],
            "Task ID": res["task_id"],
            "Exported At": res["exported_at"],
            "SHA-256": res["sha256"],
            "Verified": res["verified"],
            "Chains": len((res.get("payload") or {}).get("attack_chains") or []),
            "Traffic Records": len((res.get("payload") or {}).get("traffic_evidence") or []),
        }
        render_kv_panel(
            "RFCHunt Encrypted Archive Verification",
            summary,
            as_json=bool(getattr(args, "as_json", False)),
            plain=bool(getattr(args, "plain", False)),
        )


def cmd_all(args):
    """Execute Unified --all Scans across --repo / --path or remote --host with mandatory ModelFusion & Abliterated models."""
    from engine.mantis_integrator import DEFAULT_ABLITERATED_MODEL, run_unified_all_scans
    from engine.safe_network_validator import validate_and_authorize_target

    args.fusion = True
    args.abliteration = True
    preferred_model = DEFAULT_ABLITERATED_MODEL
    if getattr(args, "model", None) and "obliterated" in str(args.model).lower():
        preferred_model = args.model
    args.model = preferred_model

    host = getattr(args, "host", None) or getattr(args, "target", None)
    targets = getattr(args, "targets", None)
    repo = getattr(args, "repo", None)
    path = getattr(args, "path", None)
    raw_depth = getattr(args, "depth", None)
    depth = 100 if raw_depth is None else int(raw_depth)
    mode = getattr(args, "mantis_mode", "full") or "full"
    reports_dir = getattr(args, "output_dir", None) or "reports"
    authorized = bool(getattr(args, "authorized", False))
    allow_destructive = bool(getattr(args, "allow_destructive", False))
    artex_rounds = max(1, int(getattr(args, "artex_rounds", 1) or 1))
    artex_llm_profiles = _parse_csv_list(getattr(args, "artex_llm_profiles", None))

    as_json = bool(getattr(args, "as_json", False))

    artex_intent_turns = int(getattr(args, "artex_intent_turns", 0) or 0)
    artex_intent_tokens = int(getattr(args, "artex_intent_tokens", 0) or 0)
    artex_budget_turns = int(getattr(args, "artex_budget_turns", 0) or 0)
    if artex_intent_turns < 0 or artex_intent_tokens < 0 or artex_budget_turns < 0:
        print(
            "[!] ARTEX budget/turn parameters must be non-negative (>= 0).",
            file=(sys.stderr if as_json else sys.stdout),
        )
        sys.exit(1)

    if host:
        ok, reason = validate_and_authorize_target(host, authorized=authorized)
        if not ok:
            print(f"[!] Target authorization error for {host}: {reason}", file=(sys.stderr if as_json else sys.stdout))
            sys.exit(1)

    artex_live_val = getattr(args, "artex_live", None)
    if getattr(args, "no_artex_live", False):
        artex_live_val = False

    raw_port = getattr(args, "port", None)
    explicit_dests = getattr(args, "_explicit_cli_dests", set())
    if "port" in explicit_dests and raw_port is not None:
        eff_port = int(raw_port)
    elif host and str(host).strip().lower().startswith("http://"):
        if hasattr(args, "_explicit_cli_dests") or raw_port in (None, 443):
            eff_port = 80
        else:
            eff_port = int(raw_port)
    elif not host and "port" not in explicit_dests and (
        raw_port is None or (hasattr(args, "_explicit_cli_dests") and raw_port == 443)
    ):
        eff_port = None
    else:
        eff_port = 443 if raw_port is None else int(raw_port)

    db = Database(args.db)
    traces_for_render: List[Dict[str, Any]] = []
    chains_for_render: List[Dict[str, Any]] = []
    try:
        _stdout_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
        with _stdout_ctx:
            res = run_unified_all_scans(
                repo=repo or (None if (path or host or targets) else "."),
                path=path,
                host=host,
                targets=targets,
                port=eff_port,
                use_tls=getattr(args, "tls", None),
                authorized=authorized,
                allow_destructive=allow_destructive,
                depth=depth,
                mantis_mode=mode,
                use_fusion=True,
                preferred_model=preferred_model,
                db=db,
                reports_dir=reports_dir,
                artex_rounds=artex_rounds,
                artex_url=getattr(args, "artex_url", None),
                artex_token=getattr(args, "artex_token", None),
                artex_proxy=getattr(args, "artex_proxy", None),
                artex_ca_cert=getattr(args, "artex_ca_cert", None),
                artex_noise_profile=getattr(args, "artex_noise_profile", None),
                artex_llm_profiles=artex_llm_profiles,
                artex_llm_rotate=bool(getattr(args, "artex_llm_rotate", False)),
                artex_wait_sse=bool(getattr(args, "artex_wait_sse", False)),
                artex_budget_turns=int(getattr(args, "artex_budget_turns", 0) or 0),
                artex_retest=bool(getattr(args, "artex_retest", False)),
                artex_workers=int(getattr(args, "artex_workers", 3) or 3),
                artex_live=artex_live_val,
                embedded_proxy=bool(getattr(args, "embedded_proxy", False)),
                embedded_proxy_port=int(getattr(args, "embedded_proxy_port", 0) or 0),
                auth_profile=getattr(args, "auth_profile", None),
                import_har=getattr(args, "import_har", None),
                import_openapi=getattr(args, "import_openapi", None),
                scope_file=getattr(args, "scope_file", None),
                approval_mode=getattr(args, "approval_mode", "policy") or "policy",
                approval_rules=getattr(args, "approval_rules", None),
                strict_poe=bool(getattr(args, "strict_poe", False)),
                export_advisory=bool(getattr(args, "export_advisory", False)),
                export_csv=bool(getattr(args, "export_csv", False)),
                quiet=as_json,
                enable_external_scanners=bool(getattr(args, "enable_external_scanners", False)),
                httpx_scan=getattr(args, "httpx_scan", None),
                katana_scan=getattr(args, "katana_scan", None),
                nuclei_scan=getattr(args, "nuclei_scan", None),
                nuclei_tags=getattr(args, "nuclei_tags", None),
                scanner_isolation=getattr(args, "scanner_isolation", "host") or "host",
                docker_image=getattr(args, "docker_image", None),
                docker_network=getattr(args, "docker_network", None),
                artex_multiturn=bool(getattr(args, "artex_multiturn", False)),
                artex_intent_turns=artex_intent_turns,
                artex_intent_tokens=artex_intent_tokens,
                enable_rea=not bool(getattr(args, "no_rea", False)),
                rea_target=getattr(args, "rea_target", None),
                rea_use_cli=bool(getattr(args, "rea_cli", False)),
            )
        chaining_meta = res.get("attack_chaining") or {}
        tid_val = chaining_meta.get("task_id")
        if hasattr(db, "list_worker_traces"):
            traces_for_render = db.list_worker_traces(task_id=tid_val, limit=25)
        if hasattr(db, "get_attack_chains"):
            chains_for_render = db.get_attack_chains(limit=25, task_id=tid_val)
    except (PermissionError, ValueError) as exc:
        print(f"[!] Target authorization or scanner configuration error for {host or targets or repo or path}: {exc}", file=(sys.stderr if as_json else sys.stdout))
        sys.exit(1)
    finally:
        db.close()

    if getattr(args, "as_json", False):
        from engine.cli_render import render_json
        render_json(res)
        return

    from engine.cli_render import render_poe_summary
    chaining = res.get("attack_chaining") or {}
    cov = chaining.get("coverage") or {}
    poe_bd = chaining.get("poe_breakdown") or {}
    print(f"\n[+] Unified --all Security Scan Complete: target={res['target_path']} depth={depth}")
    print(f"    Fusion Enforced    : {res['fusion_enabled']} | Abliterated Model: {res['abliterated_model']}")
    print(f"    Aggregated Findings: {res['total_aggregated_findings']} {res.get('severity_counts', {})}")
    print(
        f"    ARTEX Attack Chains: {chaining.get('chains_synthesized', 0)} synthesized "
        f"(Verified: {chaining.get('exploits_verified', 0)}, Max Hops: {chaining.get('max_hop_count', 0)}, "
        f"Coverage: {cov.get('coverage_pct', 0.0)}%, Traces: {chaining.get('worker_traces_count', 0)}, Goal Proven: {chaining.get('goal_proven', False)})"
    )
    if chaining.get("error"):
        print(f"    ARTEX Error        : {chaining.get('error')}")
    print(f"    POE Breakdown      : {poe_bd}")
    print(f"    Combined SARIF     : {res['report_files'].get('combined_sarif')}")
    print(f"    Combined JSON      : {res['report_files'].get('combined_json')}")
    if res["report_files"].get("combined_csv"):
        print(f"    Combined CSV       : {res['report_files'].get('combined_csv')}")
    if res["report_files"].get("advisories"):
        print(f"    GHSA Advisories    : {len(res['report_files']['advisories'])} written")
    render_poe_summary(
        poe_bd,
        coverage=cov,
        chains=chains_for_render or chaining.get("chains") or [],
        traces=traces_for_render,
        plain=bool(getattr(args, "plain", False)),
    )


def cmd_rea(args):
    """Execute Module 21 (`morluto/rea`) client bundle, Electron `.asar`, source-map & live JS surface analyzer."""
    from engine.approval_gate import ApprovalGate
    from engine.cli_render import render_json, render_kv_panel, render_table
    from engine.dual_graph_engine import NoiseGovernor
    from engine.rea_integrator import ReaIntegrator
    from engine.safe_network_validator import (
        is_explicit_loopback_host,
        parse_host_and_port,
        validate_and_authorize_target,
    )

    as_json = bool(getattr(args, "as_json", False))
    plain = bool(getattr(args, "plain", False))
    err_stream = sys.stderr if as_json else sys.stdout
    target_path = getattr(args, "rea_target", None) or getattr(args, "path", None) or getattr(args, "repo", None)
    raw_host = getattr(args, "host", None)
    if not target_path and not raw_host:
        target_path = "."

    clean_host = None
    resolved_port = None
    resolved_tls = bool(getattr(args, "tls", False))
    authorized = bool(getattr(args, "authorized", False))

    if raw_host:
        raw_port = getattr(args, "port", None)
        explicit_dests = getattr(args, "_explicit_cli_dests", set())
        if "port" in explicit_dests and raw_port is not None:
            eff_port = int(raw_port)
        elif str(raw_host).strip().lower().startswith("http://"):
            eff_port = 80
        elif str(raw_host).strip().lower().startswith("https://"):
            eff_port = 443
        else:
            eff_port = int(raw_port) if raw_port is not None else 443
        try:
            clean_host, resolved_port, resolved_tls = parse_host_and_port(
                raw_host,
                default_port=eff_port,
                use_tls=True if getattr(args, "tls", False) else None,
            )
            ok, reason = validate_and_authorize_target(clean_host, authorized=authorized)
            if not ok:
                raise PermissionError(reason)
        except (PermissionError, ValueError) as exc:
            print(f"[!] REA target authorization error for {raw_host}: {exc}", file=err_stream)
            sys.exit(1)

    reports_dir = getattr(args, "output_dir", None) or "reports"
    approval_mode = getattr(args, "approval_mode", "policy") or "policy"
    approval_rules = getattr(args, "approval_rules", None)
    noise_profile = getattr(args, "artex_noise_profile", None)

    db = Database(args.db)
    try:
        gate = (
            ApprovalGate.from_rules_file(approval_rules, mode=approval_mode, db=db, task_id="REA-CLI")
            if approval_rules
            else ApprovalGate(mode=approval_mode, db=db, task_id="REA-CLI")
        )
        noise_gov = NoiseGovernor(profile=noise_profile)
        integrator = ReaIntegrator(
            db=db,
            reports_dir=reports_dir,
            approval_gate=gate,
            noise_governor=noise_gov,
        )
        _stdout_ctx = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
        with _stdout_ctx:
            result = integrator.analyze(
                target_path=target_path,
                host=clean_host,
                port=resolved_port,
                use_tls=resolved_tls,
                authorized=bool(authorized or (clean_host and is_explicit_loopback_host(clean_host))),
                use_rea_cli=bool(getattr(args, "rea_cli", False)),
                write_reports=True,
            )
            payload = result.to_dict()
    except (PermissionError, ValueError) as exc:
        print(f"[!] REA execution rejected: {exc}", file=err_stream)
        sys.exit(1)
    finally:
        db.close()

    if as_json:
        render_json(payload)
        return

    render_kv_panel(
        "Module 21: REA Client Surface & Artifact Audit",
        {
            "Target": payload.get("target", ""),
            "Status": payload.get("status", ""),
            "Mode": payload.get("mode", ""),
            "Findings": len(payload.get("findings") or []),
            "Endpoints Mined": len(payload.get("discovered_endpoints") or []),
            "AI Sinks Mined": len(payload.get("ai_sinks") or []),
            "Electron IPC Channels": len(payload.get("ipc_channels") or []),
            "SARIF Report": (payload.get("report_files") or {}).get("sarif", "-"),
        },
        plain=plain,
    )
    rows = [
        [
            f.get("severity", "MEDIUM"),
            f.get("rule_id", ""),
            f.get("title", ""),
            f"{f.get('file_path', '')}:{f.get('line_number', 1)}",
        ]
        for f in (payload.get("findings") or [])
    ]
    render_table("REA Surface & Bundle Findings", ["Severity", "Rule ID", "Title", "Location"], rows, plain=plain)


def cmd_harness2(args):
    """Executes Google Research Harness² recursive agent harnessing (Propose-Probe-Compose across c1..c8)."""
    from engine.harness2_engine import Harness2ProtocolEngine
    from engine.safe_network_validator import validate_and_authorize_target

    target_host = getattr(args, "host", None) or getattr(args, "target", None) or "127.0.0.1"
    ok, reason = validate_and_authorize_target(target_host, authorized=getattr(args, "authorized", False))
    if not ok:
        print(f"[!] Target authorization error for {target_host}: {reason}")
        sys.exit(1)

    db = Database(args.db)
    try:
        engine = Harness2ProtocolEngine(
            runs_root=args.runs_dir,
            target_host=target_host,
            target_port=args.port,
            db_path=args.db,
        )
        if args.report:
            print(engine.format_cli_report(db_instance=db))
            return

        rfcs = [r.strip() for r in str(args.rfc).split(",") if r.strip()]
        with HostContainmentManager():
            summary = engine.run_suite(
                rfc_list=rfcs,
                k=args.k,
                mode=args.mode,
                domain=args.domain,
                db_instance=db,
            )
        print(engine.format_cli_report(summary=summary, db_instance=db))
    finally:
        db.close()


def main():
    class _WideRawHelpFormatter(argparse.RawDescriptionHelpFormatter):
        def __init__(
            self,
            prog: str,
            indent_increment: int = 2,
            max_help_position: int = 24,
            width: Optional[int] = None,
        ) -> None:
            super().__init__(
                prog,
                indent_increment=indent_increment,
                max_help_position=max_help_position,
                width=max(240, width or 240),
            )

    class _TrackExplicitStore(argparse.Action):
        def __call__(self, parser_obj, namespace, values, option_string=None):
            setattr(namespace, self.dest, values)
            explicit_set = getattr(namespace, "_explicit_cli_dests", None)
            if explicit_set is None:
                explicit_set = set()
                setattr(namespace, "_explicit_cli_dests", explicit_set)
            explicit_set.add(self.dest)

    parser = argparse.ArgumentParser(
        usage="%(prog)s [GLOBAL_OPTIONS] <command> [COMMAND_OPTIONS]",
        description="""
===============================================================================
HTTP TERMINATOR: Autonomous Protocol Compliance & Security Research CLI
===============================================================================
Modular command-line interface for fetching IETF RFC specifications, extracting
terminator-weighted micro-inspiration fragments, generating edge-case protocol
probes via local LLMs, applying 25 wire/chunk/cross-protocol terminator
permutations, and evaluating differential state behavior.
""",
        epilog="""
===============================================================================
USAGE EXAMPLES:
===============================================================================

1. Run the unified 'Build All' verification pipeline (syntax, DB, 25 RFC cache, pytest):
   python main.py build

2. Start the local Test Lab Server on 127.0.0.1:8080:
   python main.py lab --host 127.0.0.1 --port 8080

3. Run a full autonomous research cycle (Fetch -> Chunk -> Generate -> Permute -> Evaluate -> Dream-RSI):
   python main.py auto --target 127.0.0.1 --port 8080 --concurrency 4

4. Continuously hunt across Terminator RFCs (starting with RFC 9112):
   python main.py hunt --target target.example.com --port 443 --tls --max-rfcs 15

5. Step-by-step modular pipeline execution:
   python main.py fetch --count 5
   python main.py chunk --sentences 2
   python main.py generate --limit 5
   python main.py permute --limit 10 --variants 5
   python main.py evaluate --target 127.0.0.1 --port 8080 --concurrency 8

6. Measure front-end proxy byte transformations with Protocol Ruler:
   python main.py ruler --target target.example.com --port 443 --tls --debug

7. Run offline Dream-RSI recursive self-improvement on historical database probes:
   python main.py dream --db terminator.db --rollouts 300 --generations 3

8. Export confirmed findings to a MITRE Caldera adversary emulation plugin:
   python main.py caldera --export ./caldera_export

9. Run Google Research Harness² recursive agent harnessing (Propose-Probe-Compose across c1..c8):
   python main.py harness2 --rfc 9112 --k 2 --mode both
===============================================================================
""",
        formatter_class=_WideRawHelpFormatter,
    )
    parser.add_argument("--db", default="terminator.db", help="SQLite database path")
    parser.add_argument("--clean-db", action="store_true", help="Clean the SQLite database (truncate transient tables and VACUUM) before running")
    parser.add_argument("--keep-rfcs-on-clean", "--keep-rfcs", dest="keep_rfcs_on_clean", action="store_true", help="Retain cached RFC specifications when cleaning the database")
    parser.add_argument("--keep-findings-on-clean", "--keep-findings", dest="keep_findings_on_clean", action="store_true", help="Retain confirmed findings when cleaning the database")
    parser.add_argument("--model", default="hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M", help="Preferred base model (default: refusal-free hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M)")
    parser.add_argument("--sec-model", default=None, help="Secondary security specialist model (default: Cisco fenkohq/foundation-sec-8b:latest / abliterated)")
    parser.add_argument("--abliteration", "--obliterated", dest="abliteration", action="store_true", default=True, help="Default ON: Use refusal-free abliterated models (no safety filtering) across ModelFusion panel (Gemma + Cisco Foundation-Sec + GLM)")
    parser.add_argument("--no-fusion", dest="fusion", action="store_false", help="Disable multi-model panel fusion")
    parser.add_argument("--all", "--run-all", "--all-scans", dest="run_all_scans", action="store_true", help="Run ALL integrated scanners (Google Mantis, aiscan, ARTEX, RAPTOR, Prompt Smuggling) with mandatory Fusion & Abliterated models")
    parser.add_argument("--mantis", action="store_true", help="Run Google Mantis (Module 20) scan")
    parser.add_argument("--repo", dest="repo", type=str, default=None, help="Repository path for --all / --mantis scan")
    parser.add_argument("--path", dest="path", type=str, default=None, help="Target file or folder path for --all / --mantis scan")
    parser.add_argument("--host", "--target", dest="host", type=str, default=None, help="Target host (domain or IP)")
    parser.add_argument("--targets", dest="targets", type=str, default=None, help="Comma-separated target endpoints for differential scans (e.g. '127.0.0.1:8080,target.example.com:443')")
    parser.add_argument("--port", type=int, default=443, action=_TrackExplicitStore, help="Target port (default: 443)")
    parser.add_argument("--tls", action="store_true", help="Enable TLS/HTTPS for target host")
    parser.add_argument("--authorized", action="store_true", help="Explicitly authorize active security testing against remote/public target")
    parser.add_argument("--allow-destructive", action="store_true", help="Explicitly permit state-mutating requests (PUT, DELETE, PATCH) and active response theft on authorized targets")
    parser.add_argument("--depth", dest="depth", type=int, default=None, help="Google Mantis scan depth (1..100, default: 100 for --all, 30 for mantis)")
    parser.add_argument("--mantis-mode", dest="mantis_mode", choices=["full", "fast", "threat-model", "scan", "reproduce", "patch"], default="full", help="Google Mantis pipeline mode")
    parser.add_argument("--output-dir", dest="output_dir", type=str, default="reports", help="Output directory for SARIF/JSON audit reports")
    parser.add_argument("--artex-rounds", dest="artex_rounds", type=int, default=1, action=_TrackExplicitStore, help="Number of ARTEX Dual-Graph planning & attack chaining rounds (default: 1)")
    parser.add_argument("--artex-url", dest="artex_url", type=str, default=None, help="Optional headless BaaRai/ARTEX REST+SSE server URL (e.g. http://127.0.0.1:8787)")
    parser.add_argument("--artex-token", dest="artex_token", type=str, default=None, help="Optional Bearer JWT token for headless ARTEX REST API")
    parser.add_argument("--artex-proxy", dest="artex_proxy", type=str, default=None, help="Optional ARTEX recording MITM proxy URL (e.g. http://127.0.0.1:8788)")
    parser.add_argument("--artex-ca-cert", dest="artex_ca_cert", type=str, default=None, help="Optional CA certificate path for ARTEX MITM proxy verification")
    parser.add_argument("--artex-noise-profile", dest="artex_noise_profile", choices=["off", "quiet", "balanced", "aggressive"], default=None, help="Target traffic noise governor profile (off|quiet|balanced|aggressive)")
    parser.add_argument("--artex-llm-profiles", dest="artex_llm_profiles", type=str, default=None, help="Comma-separated LLM profile IDs for ARTEX worker rotation")
    parser.add_argument("--artex-llm-rotate", dest="artex_llm_rotate", action="store_true", default=False, help="Enable round-robin multi-LLM worker rotation (A, B, A, B)")
    parser.add_argument("--artex-wait-sse", dest="artex_wait_sse", action="store_true", default=False, help="Stream ARTEX SSE activity events until terminal task completion")
    parser.add_argument("--artex-budget-turns", dest="artex_budget_turns", type=int, default=0, help="Optional max task turn budget for ARTEX attack chaining (0 = unlimited)")
    parser.add_argument("--artex-retest", dest="artex_retest", action="store_true", default=False, help="Run ARTEX chain retest loop after synthesis")
    parser.add_argument("--artex-workers", dest="artex_workers", type=int, default=3, help="Concurrent ARTEX worker pool size (default: 3)")
    parser.add_argument("--artex-live", dest="artex_live", action="store_true", default=None, help="Force live non-destructive ARTEX worker verification against authorized targets")
    parser.add_argument("--no-artex-live", dest="no_artex_live", action="store_true", default=False, help="Disable auto-live ARTEX worker verification")
    parser.add_argument("--embedded-proxy", dest="embedded_proxy", action="store_true", default=False, help="Start embedded pure-CLI recording MITM proxy during scan")
    parser.add_argument("--embedded-proxy-port", dest="embedded_proxy_port", type=int, default=0, help="Port for embedded MITM proxy (0 = ephemeral)")
    parser.add_argument("--auth-profile", dest="auth_profile", type=str, default=None, help="Path to JSON/YAML multi-role auth profiles (e.g. end_user_oidc vs service)")
    parser.add_argument("--import-har", dest="import_har", type=str, default=None, help="Import HAR 1.2 recording into AssetGraph + traffic_evidence")
    parser.add_argument("--import-openapi", dest="import_openapi", type=str, default=None, help="Import OpenAPI 3.x / Swagger 2.0 spec into AssetGraph")
    parser.add_argument("--scope-file", dest="scope_file", type=str, default=None, help="Path to YAML/JSON allow/deny scope rules")
    parser.add_argument("--approval-mode", dest="approval_mode", choices=["policy", "prompt", "deny"], default="policy", help="Approval gate mode (policy|prompt|deny)")
    parser.add_argument("--approval-rules", dest="approval_rules", type=str, default=None, help="Path to YAML/JSON approval rules file (argv_prefix/host/method)")
    parser.add_argument("--strict-poe", dest="strict_poe", action="store_true", default=False, help="Require POE>=2 (active anomaly / live receipt) to mark chains VERIFIED")
    parser.add_argument("--export-advisory", dest="export_advisory", action="store_true", default=False, help="Export GHSA-ready Markdown advisories for chains")
    parser.add_argument("--export-csv", dest="export_csv", action="store_true", default=False, help="Export formula-neutralized CSV of findings & chains")
    parser.add_argument("--enable-external-scanners", dest="enable_external_scanners", action="store_true", default=False, help="Opt-in to external black-box scanners (httpx, katana, nuclei)")
    parser.add_argument("--httpx-scan", dest="httpx_scan", action="store_true", default=None, help="Opt-in to ProjectDiscovery httpx discovery")
    parser.add_argument("--katana-scan", dest="katana_scan", action="store_true", default=None, help="Opt-in to ProjectDiscovery katana crawling")
    parser.add_argument("--nuclei-scan", dest="nuclei_scan", action="store_true", default=None, help="Opt-in to ProjectDiscovery nuclei non-destructive scanning")
    parser.add_argument("--nuclei-tags", dest="nuclei_tags", type=str, default=None, help="Comma-separated non-destructive nuclei tags (e.g. tech,misconfig,exposure,headers)")
    parser.add_argument("--scanner-isolation", dest="scanner_isolation", choices=["host", "docker"], default="host", help="External scanner execution isolation mode (host|docker)")
    parser.add_argument("--docker-image", dest="docker_image", type=str, default=None, help="Optional explicit OCI image for docker isolation")
    parser.add_argument("--docker-network", dest="docker_network", choices=["bridge", "none"], default=None, help="Docker network mode for external scanner isolation (bridge|none)")
    parser.add_argument("--artex-multiturn", dest="artex_multiturn", action="store_true", default=False, help="Enable bounded multi-turn ArtexWorker adaptive tool loop")
    parser.add_argument("--artex-intent-turns", dest="artex_intent_turns", type=int, default=0, help="Max turns per ARTEX intent (0 = default/unlimited)")
    parser.add_argument("--artex-intent-tokens", dest="artex_intent_tokens", type=int, default=0, help="Max tokens per ARTEX intent (0 = unlimited)")
    parser.add_argument("--rea-target", dest="rea_target", type=str, default=None, help="Optional explicit JS/Electron/.asar/web bundle path for Module 21 REA surface analysis")
    parser.add_argument("--rea-cli", dest="rea_cli", action="store_true", default=False, help="Opt-in to locally installed rea-agents CLI (shell=False) alongside Python REA inspector")
    parser.add_argument("--no-rea", dest="no_rea", action="store_true", default=False, help="Disable Module 21 REA client bundle & Electron surface analysis during --all")
    parser.add_argument("--json", dest="as_json", action="store_true", default=False, help="Emit machine-readable JSON output")
    parser.add_argument("--plain", dest="plain", action="store_true", default=False, help="Force plain ASCII output without ANSI/Rich formatting")
    parser.set_defaults(fusion=True)

    subparsers = parser.add_subparsers(dest="command")

    # Protocol Ruler (James Kettle benchmark technique)
    p_ruler = subparsers.add_parser("ruler", help="Execute Protocol Ruler byte-transformation measurement (James Kettle technique)")
    p_ruler.add_argument("--target", default="127.0.0.1", help="Target host")
    p_ruler.add_argument("--port", type=int, default=8080, help="Target port")
    p_ruler.add_argument("--tls", action="store_true", help="Use TLS")
    p_ruler.add_argument("--timeout", type=float, default=3.5, help="Socket timeout")
    p_ruler.add_argument("--max-size", type=int, default=131072, help="Max header length to test in bytes")
    p_ruler.add_argument("--sequence", type=str, default=None, help="Custom byte sequence to test")
    p_ruler.add_argument("--name", type=str, default="Custom Probe", help="Name for custom sequence")
    p_ruler.add_argument("--debug", action="store_true", help="Enable deep bracket and binary search tracing")
    p_ruler.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # Hunt (Continuous until flaws found)
    p_hunt = subparsers.add_parser("hunt", help="Continuously fetch RFCs and hunt for flaws")
    p_hunt.add_argument("--target", default="127.0.0.1", help="Target host")
    p_hunt.add_argument("--port", type=int, default=8080, help="Target port")
    p_hunt.add_argument("--tls", action="store_true", help="Use TLS")
    p_hunt.add_argument("--max-rfcs", type=int, default=15, help="Maximum RFCs to cycle through")
    p_hunt.add_argument("--fragments", type=int, default=3, help="Fragments per RFC")
    p_hunt.add_argument("--variants", type=int, default=2, help="Permutations per probe")
    p_hunt.add_argument("--keep-going", action="store_true", help="Don't stop on first flaw; continue discovering")

    # MCP Server (stdio, Streamable HTTP /http, Legacy SSE /sse)
    p_mcp = subparsers.add_parser("mcp", help="Run MCP Server over stdio, Streamable HTTP (/http), or Legacy SSE (/sse) for ARTEX")
    p_mcp.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")
    p_mcp.add_argument("--transport", choices=["stdio", "http", "sse", "both"], default="stdio", help="MCP transport mode (default: stdio)")
    p_mcp.add_argument("--mcp-host", default="127.0.0.1", help="Bind host for HTTP/SSE MCP server (default: 127.0.0.1)")
    p_mcp.add_argument("--mcp-port", type=int, default=8790, help="Bind port for HTTP/SSE MCP server (default: 8790)")
    p_mcp.add_argument("--mcp-token", default=None, help="Optional Bearer token for remote HTTP/SSE MCP clients")

    # Fetch
    p_fetch = subparsers.add_parser("fetch", help="Fetch RFC documents")
    p_fetch.add_argument("--count", type=int, default=3, help="Number of core RFCs to fetch")
    p_fetch.add_argument("--cache-dir", default="rfcs", help="Local directory to store RFCs")
    p_fetch.add_argument("--discover-recent", type=int, default=0, help="Discover recent RFCs from index")

    # Chunk
    p_chunk = subparsers.add_parser("chunk", help="Chunk RFCs into micro-inspiration fragments")
    p_chunk.add_argument("--sentences", type=int, default=2, help="Sentences per chunk")

    # Generate
    p_gen = subparsers.add_parser("generate", help="Generate novel probes with LLM")
    p_gen.add_argument("--limit", type=int, default=5, help="Fragments to process")

    # Permute
    p_perm = subparsers.add_parser("permute", help="Apply vector permutations to base probes")
    p_perm.add_argument("--limit", type=int, default=10, help="Base probes to permute")
    p_perm.add_argument("--variants", type=int, default=3, help="Variants per probe")

    # Evaluate
    p_eval = subparsers.add_parser("evaluate", help="Run deterministic evaluation harness")
    p_eval.add_argument("--target", default="127.0.0.1", help="Target host")
    p_eval.add_argument("--port", type=int, default=8080, help="Target port")
    p_eval.add_argument("--tls", action="store_true", help="Use TLS")
    p_eval.add_argument("--timeout", type=float, default=3.0, help="Socket timeout")
    p_eval.add_argument("--limit", type=int, default=20, help="Probes to evaluate")
    p_eval.add_argument("--concurrency", "--threads", type=int, default=4, help="Maximum concurrent probe evaluation threads (default: 4)")

    # Weaponize
    p_weap = subparsers.add_parser("weaponize", help="Execute dangling-byte RQP")
    p_weap.add_argument("--target", default="127.0.0.1", help="Target host")
    p_weap.add_argument("--port", type=int, default=8080, help="Target port")
    p_weap.add_argument("--tls", action="store_true", help="Use TLS")

    # Cascade
    p_casc = subparsers.add_parser("cascade", help="Run discovery cascade on findings")
    p_casc.add_argument("--demo", action="store_true", help="Run with demonstration finding if none confirmed yet")

    # Lab
    p_lab = subparsers.add_parser("lab", help="Run local test lab server")
    p_lab.add_argument("--host", default="127.0.0.1", help="Host interface")
    p_lab.add_argument("--port", type=int, default=8080, help="Port")
    p_lab.add_argument("--patched", action="store_true", default=False, help="Start lab with /internal/service auth-boundary patched (returns 403)")

    # Auto
    p_auto = subparsers.add_parser("auto", help="Run complete continuous autonomous loop")
    p_auto.add_argument("--count", type=int, default=3, help="Number of RFCs to fetch")
    p_auto.add_argument("--cache-dir", default="rfcs", help="Local directory to store RFCs")
    p_auto.add_argument("--discover-recent", type=int, default=0, help="Discover recent RFCs")
    p_auto.add_argument("--sentences", type=int, default=2, help="Sentences per chunk")
    p_auto.add_argument("--limit", type=int, default=3, help="Fragments to generate")
    p_auto.add_argument("--variants", type=int, default=2, help="Variants per probe")
    p_auto.add_argument("--target", default="127.0.0.1", help="Target host")
    p_auto.add_argument("--port", type=int, default=8080, help="Target port")
    p_auto.add_argument("--tls", action="store_true", help="Use TLS")
    p_auto.add_argument("--timeout", type=float, default=3.0, help="Socket timeout")
    p_auto.add_argument("--concurrency", "--threads", type=int, default=4, help="Maximum concurrent probe evaluation threads (default: 4)")
    p_auto.add_argument("--no-dream-rsi", action="store_true", help="Disable default Dream-RSI evolution cycle")
    p_auto.add_argument("--rollouts", type=int, default=200, help="Rollouts per candidate policy (default: 200)")
    p_auto.add_argument("--generations", type=int, default=2, help="Evolutionary dream generations (default: 2)")
    p_auto.add_argument("--export", default="data/dream_policies.json", help="Path to export evolved policies")
    # Dream (Open Dream-RSI: Off-Policy Recursive Self-Improvement)
    p_dream = subparsers.add_parser("dream", help="Run offline Dream-RSI policy evolution")
    p_dream.add_argument("--db", default=argparse.SUPPRESS, help="Path to database with exploration history")
    p_dream.add_argument("--target", default="127.0.0.1", help="Target host")
    p_dream.add_argument("--port", type=int, default=5006, help="Target port")
    p_dream.add_argument("--rollouts", type=int, default=300, help="Rollouts per candidate policy")
    p_dream.add_argument("--generations", type=int, default=3, help="Evolutionary dream generations")
    p_dream.add_argument("--export", default="data/dream_policies.json", help="Path to export evolved policies")

    # Caldera (Adversary Emulation Integration)
    p_caldera = subparsers.add_parser("caldera", help="Export or push findings to Caldera adversary emulation")
    p_caldera.add_argument("--export", type=str, default=None, help="Directory to export Caldera plugin structure")
    p_caldera.add_argument("--push", type=str, default=None, help="Caldera server URL to push abilities live")
    p_caldera.add_argument("--api-key", type=str, default=None, help="Caldera API key for REST authentication")

    # Harness2 (Google Research Recursive Agent Harnessing)
    p_harness2 = subparsers.add_parser("harness2", help="Run Google Research Harness2 recursive agent harnessing (c1..c8)")
    p_harness2.add_argument("--rfc", default="9112", help="Target RFC number(s) (e.g. 9112 or 9112,9110,9113)")
    p_harness2.add_argument("--k", "--harness2-k", dest="k", type=int, default=1, help="Recursion parameter k (R=4k rollouts, P=3k stages)")
    p_harness2.add_argument("--mode", "--harness2-mode", dest="mode", choices=["parallel", "sequential", "agg", "seq", "both"], default="parallel", help="Recursion topology: parallel (agg width), sequential (seq depth), or both")
    p_harness2.add_argument("--domain", "--harness2-domain", dest="domain", default="auto", help="Protocol domain for experience library")
    p_harness2.add_argument("--runs-dir", "--harness2-runs-dir", dest="runs_dir", default="runs/harness2", help="Directory for persisted Harness2 runs and experience library")
    p_harness2.add_argument("--host", "--target", dest="host", default=argparse.SUPPRESS, help="Target host (domain or IP)")
    p_harness2.add_argument("--authorized", action="store_true", default=argparse.SUPPRESS, help="Explicitly authorize active testing")
    p_harness2.add_argument("--port", type=int, default=8080, help="Target port")
    p_harness2.add_argument("--report", "--harness2-report", dest="report", action="store_true", help="Print historical Harness2 runs and experience libraries")

    # Google Mantis & Unified All Scans
    p_all = subparsers.add_parser("all", help="Run ALL security scanners (Mantis, aiscan, ARTEX, RAPTOR, Prompt Smuggling) with Fusion + Abliterated models")
    p_all.add_argument("--repo", default=argparse.SUPPRESS, help="Repository directory path")
    p_all.add_argument("--path", default=argparse.SUPPRESS, help="File or directory path")
    p_all.add_argument("--host", "--target", dest="host", default=argparse.SUPPRESS, help="Target host (domain or IP)")
    p_all.add_argument("--targets", dest="targets", default=argparse.SUPPRESS, help="Comma-separated target endpoints for multi-target differential scans")
    p_all.add_argument("--port", type=int, default=argparse.SUPPRESS, action=_TrackExplicitStore, help="Target port")
    p_all.add_argument("--tls", action="store_true", default=argparse.SUPPRESS, help="Enable TLS/HTTPS for target host")
    p_all.add_argument("--authorized", action="store_true", default=argparse.SUPPRESS, help="Explicitly authorize active testing")
    p_all.add_argument("--allow-destructive", action="store_true", default=argparse.SUPPRESS, help="Permit state-mutating requests")
    p_all.add_argument("--depth", type=int, default=None, help="Mantis depth (1..100, default: 100)")
    p_all.add_argument("--mantis-mode", choices=["full", "fast", "threat-model", "scan", "reproduce", "patch"], default=argparse.SUPPRESS, help="Mantis mode")
    p_all.add_argument("--output-dir", default=argparse.SUPPRESS, help="Report output directory")
    p_all.add_argument("--artex-rounds", type=int, default=argparse.SUPPRESS, help="ARTEX Dual-Graph planning rounds")
    p_all.add_argument("--artex-url", default=argparse.SUPPRESS, help="Headless ARTEX REST+SSE server URL")
    p_all.add_argument("--artex-token", default=argparse.SUPPRESS, help="Headless ARTEX Bearer token")
    p_all.add_argument("--artex-proxy", default=argparse.SUPPRESS, help="ARTEX recording MITM proxy URL (:8788)")
    p_all.add_argument("--artex-ca-cert", default=argparse.SUPPRESS, help="ARTEX MITM proxy CA cert path")
    p_all.add_argument("--artex-noise-profile", choices=["off", "quiet", "balanced", "aggressive"], default=argparse.SUPPRESS, help="ARTEX target noise governor profile")
    p_all.add_argument("--artex-llm-profiles", default=argparse.SUPPRESS, help="Comma-separated LLM profile IDs for rotation")
    p_all.add_argument("--artex-llm-rotate", action="store_true", default=argparse.SUPPRESS, help="Enable multi-LLM worker rotation")
    p_all.add_argument("--artex-wait-sse", action="store_true", default=argparse.SUPPRESS, help="Wait for headless ARTEX SSE events")
    p_all.add_argument("--artex-budget-turns", type=int, default=argparse.SUPPRESS, help="Max ARTEX task turns")
    p_all.add_argument("--artex-retest", action="store_true", default=argparse.SUPPRESS, help="Run chain retest loop")
    p_all.add_argument("--artex-workers", type=int, default=argparse.SUPPRESS, help="Concurrent ARTEX worker pool size")
    p_all.add_argument("--artex-live", action="store_true", default=argparse.SUPPRESS, help="Force live ARTEX verification")
    p_all.add_argument("--no-artex-live", action="store_true", default=argparse.SUPPRESS, help="Disable auto-live ARTEX verification")
    p_all.add_argument("--embedded-proxy", action="store_true", default=argparse.SUPPRESS, help="Start embedded recording MITM proxy")
    p_all.add_argument("--embedded-proxy-port", type=int, default=argparse.SUPPRESS, help="Embedded MITM proxy port")
    p_all.add_argument("--auth-profile", default=argparse.SUPPRESS, help="Auth profiles JSON/YAML path")
    p_all.add_argument("--import-har", default=argparse.SUPPRESS, help="Import HAR 1.2 file into AssetGraph")
    p_all.add_argument("--import-openapi", default=argparse.SUPPRESS, help="Import OpenAPI/Swagger spec into AssetGraph")
    p_all.add_argument("--scope-file", default=argparse.SUPPRESS, help="Scope allow/deny YAML/JSON file")
    p_all.add_argument("--approval-mode", choices=["policy", "prompt", "deny"], default=argparse.SUPPRESS, help="Approval gate mode")
    p_all.add_argument("--approval-rules", default=argparse.SUPPRESS, help="Approval rules YAML/JSON file")
    p_all.add_argument("--strict-poe", action="store_true", default=argparse.SUPPRESS, help="Enforce strict POE>=2")
    p_all.add_argument("--export-advisory", action="store_true", default=argparse.SUPPRESS, help="Export GHSA Markdown advisories")
    p_all.add_argument("--export-csv", action="store_true", default=argparse.SUPPRESS, help="Export formula-safe CSV")
    p_all.add_argument("--enable-external-scanners", dest="enable_external_scanners", action="store_true", default=argparse.SUPPRESS, help="Opt-in to external black-box scanners (httpx, katana, nuclei)")
    p_all.add_argument("--httpx-scan", dest="httpx_scan", action="store_true", default=argparse.SUPPRESS, help="Opt-in to ProjectDiscovery httpx discovery")
    p_all.add_argument("--katana-scan", dest="katana_scan", action="store_true", default=argparse.SUPPRESS, help="Opt-in to ProjectDiscovery katana crawling")
    p_all.add_argument("--nuclei-scan", dest="nuclei_scan", action="store_true", default=argparse.SUPPRESS, help="Opt-in to ProjectDiscovery nuclei non-destructive scanning")
    p_all.add_argument("--nuclei-tags", dest="nuclei_tags", type=str, default=argparse.SUPPRESS, help="Comma-separated non-destructive nuclei tags")
    p_all.add_argument("--scanner-isolation", dest="scanner_isolation", choices=["host", "docker"], default=argparse.SUPPRESS, help="External scanner isolation mode (host|docker)")
    p_all.add_argument("--docker-image", dest="docker_image", type=str, default=argparse.SUPPRESS, help="Optional explicit OCI image for docker isolation")
    p_all.add_argument("--docker-network", dest="docker_network", choices=["bridge", "none"], default=argparse.SUPPRESS, help="Docker network mode for external scanner isolation (bridge|none)")
    p_all.add_argument("--artex-multiturn", dest="artex_multiturn", action="store_true", default=argparse.SUPPRESS, help="Enable bounded multi-turn ArtexWorker adaptive tool loop")
    p_all.add_argument("--artex-intent-turns", dest="artex_intent_turns", type=int, default=argparse.SUPPRESS, help="Max turns per ARTEX intent")
    p_all.add_argument("--artex-intent-tokens", dest="artex_intent_tokens", type=int, default=argparse.SUPPRESS, help="Max tokens per ARTEX intent")
    p_all.add_argument("--rea-target", dest="rea_target", type=str, default=argparse.SUPPRESS, help="Optional explicit JS/Electron/.asar/web bundle path for Module 21 REA")
    p_all.add_argument("--rea-cli", dest="rea_cli", action="store_true", default=argparse.SUPPRESS, help="Opt-in to locally installed rea-agents CLI")
    p_all.add_argument("--no-rea", dest="no_rea", action="store_true", default=argparse.SUPPRESS, help="Disable Module 21 REA during --all")
    p_all.add_argument("--json", dest="as_json", action="store_true", default=argparse.SUPPRESS, help="Emit JSON output")
    p_all.add_argument("--plain", action="store_true", default=argparse.SUPPRESS, help="Plain ASCII output")
    p_all.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")

    # BaaRai/ARTEX Dual-Graph & Durable Attack Chaining subcommand
    for _cmd_name in ("artex", "chain"):
        p_artex = subparsers.add_parser(_cmd_name, help="Run BaaRai/ARTEX Dual-Graph durable attack chaining & headless REST/SSE sync")
        p_artex.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")
        p_artex.add_argument("--host", "--target", dest="host", default=argparse.SUPPRESS, help="Target host (default: 127.0.0.1)")
        p_artex.add_argument("--port", type=int, default=argparse.SUPPRESS, action=_TrackExplicitStore, help="Target port (default: 8080)")
        p_artex.add_argument("--tls", action="store_true", default=argparse.SUPPRESS, help="Enable TLS/HTTPS")
        p_artex.add_argument("--authorized", action="store_true", default=argparse.SUPPRESS, help="Explicitly authorize remote target")
        p_artex.add_argument("--allow-destructive", action="store_true", default=argparse.SUPPRESS, help="Permit state-mutating requests")
        p_artex.add_argument("--artex-rounds", "--rounds", dest="artex_rounds", type=int, default=argparse.SUPPRESS, action=_TrackExplicitStore, help="Multi-round planning cycles (default: 2)")
        p_artex.add_argument("--artex-url", default=argparse.SUPPRESS, help="Headless ARTEX REST+SSE server URL (e.g. http://127.0.0.1:8787)")
        p_artex.add_argument("--artex-token", default=argparse.SUPPRESS, help="Headless ARTEX Bearer JWT token")
        p_artex.add_argument("--artex-proxy", default=argparse.SUPPRESS, help="ARTEX MITM proxy URL (e.g. http://127.0.0.1:8788)")
        p_artex.add_argument("--artex-ca-cert", default=argparse.SUPPRESS, help="ARTEX MITM CA cert path")
        p_artex.add_argument("--artex-noise-profile", choices=["off", "quiet", "balanced", "aggressive"], default=argparse.SUPPRESS, help="Noise governor profile")
        p_artex.add_argument("--artex-llm-profiles", default=argparse.SUPPRESS, help="Comma-separated LLM profile IDs")
        p_artex.add_argument("--artex-llm-rotate", action="store_true", default=argparse.SUPPRESS, help="Enable multi-LLM worker rotation")
        p_artex.add_argument("--artex-wait-sse", action="store_true", default=argparse.SUPPRESS, help="Stream headless ARTEX SSE events")
        p_artex.add_argument("--artex-budget-turns", type=int, default=argparse.SUPPRESS, help="Max task turn budget")
        p_artex.add_argument("--artex-multiturn", dest="artex_multiturn", action="store_true", default=argparse.SUPPRESS, help="Enable bounded multi-turn ArtexWorker adaptive tool loop")
        p_artex.add_argument("--artex-intent-turns", dest="artex_intent_turns", type=int, default=argparse.SUPPRESS, help="Max turns per ARTEX intent")
        p_artex.add_argument("--artex-intent-tokens", dest="artex_intent_tokens", type=int, default=argparse.SUPPRESS, help="Max tokens per ARTEX intent")
        p_artex.add_argument("--artex-retest", "--retest", dest="artex_retest", action="store_true", default=argparse.SUPPRESS, help="Retest persisted attack chains")
        p_artex.add_argument("--artex-workers", type=int, default=argparse.SUPPRESS, help="Concurrent ARTEX worker pool size")
        p_artex.add_argument("--artex-live", action="store_true", default=argparse.SUPPRESS, help="Force live ARTEX verification")
        p_artex.add_argument("--no-artex-live", action="store_true", default=argparse.SUPPRESS, help="Disable auto-live ARTEX verification")
        p_artex.add_argument("--embedded-proxy", action="store_true", default=argparse.SUPPRESS, help="Start embedded recording MITM proxy")
        p_artex.add_argument("--embedded-proxy-port", type=int, default=argparse.SUPPRESS, help="Embedded MITM proxy port")
        p_artex.add_argument("--auth-profile", default=argparse.SUPPRESS, help="Auth profiles JSON/YAML path")
        p_artex.add_argument("--import-har", default=argparse.SUPPRESS, help="Import HAR 1.2 file into AssetGraph")
        p_artex.add_argument("--import-openapi", default=argparse.SUPPRESS, help="Import OpenAPI/Swagger spec into AssetGraph")
        p_artex.add_argument("--scope-file", default=argparse.SUPPRESS, help="Scope allow/deny YAML/JSON file")
        p_artex.add_argument("--approval-mode", choices=["policy", "prompt", "deny"], default=argparse.SUPPRESS, help="Approval gate mode")
        p_artex.add_argument("--approval-rules", default=argparse.SUPPRESS, help="Approval rules YAML/JSON file")
        p_artex.add_argument("--strict-poe", action="store_true", default=argparse.SUPPRESS, help="Enforce strict POE>=2")
        p_artex.add_argument("--export-advisory", action="store_true", default=argparse.SUPPRESS, help="Export GHSA Markdown advisories")
        p_artex.add_argument("--export-csv", action="store_true", default=argparse.SUPPRESS, help="Export formula-safe CSV")
        p_artex.add_argument("--output-dir", default=argparse.SUPPRESS, help="Report output directory")
        p_artex.add_argument("--json", dest="as_json", action="store_true", default=argparse.SUPPRESS, help="Emit JSON output")
        p_artex.add_argument("--plain", action="store_true", default=argparse.SUPPRESS, help="Plain ASCII output")

    p_artex_loop = subparsers.add_parser("artex-loop", help="Run bounded multi-turn ArtexWorker adaptive tool loop")
    p_artex_loop.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")
    p_artex_loop.add_argument("--host", "--target", dest="host", default=argparse.SUPPRESS, help="Target host (default: 127.0.0.1)")
    p_artex_loop.add_argument("--port", type=int, default=argparse.SUPPRESS, action=_TrackExplicitStore, help="Target port (default: 8080)")
    p_artex_loop.add_argument("--tls", action="store_true", default=argparse.SUPPRESS, help="Enable TLS/HTTPS")
    p_artex_loop.add_argument("--authorized", action="store_true", default=argparse.SUPPRESS, help="Explicitly authorize remote target")
    p_artex_loop.add_argument("--allow-destructive", action="store_true", default=argparse.SUPPRESS, help="Permit state-mutating requests")
    p_artex_loop.add_argument("--artex-rounds", "--rounds", dest="artex_rounds", type=int, default=argparse.SUPPRESS, action=_TrackExplicitStore, help="Planning cycles (default: 1)")
    p_artex_loop.add_argument("--artex-noise-profile", choices=["off", "quiet", "balanced", "aggressive"], default=argparse.SUPPRESS, help="Noise governor profile")
    p_artex_loop.add_argument("--artex-budget-turns", type=int, default=argparse.SUPPRESS, help="Max task turn budget")
    p_artex_loop.add_argument("--artex-multiturn", dest="artex_multiturn", action="store_true", default=argparse.SUPPRESS, help="Enable bounded multi-turn ArtexWorker adaptive tool loop")
    p_artex_loop.add_argument("--artex-intent-turns", dest="artex_intent_turns", type=int, default=argparse.SUPPRESS, help="Max turns per ARTEX intent")
    p_artex_loop.add_argument("--artex-intent-tokens", dest="artex_intent_tokens", type=int, default=argparse.SUPPRESS, help="Max tokens per ARTEX intent")
    p_artex_loop.add_argument("--artex-workers", type=int, default=argparse.SUPPRESS, help="Concurrent ARTEX worker pool size")
    p_artex_loop.add_argument("--artex-live", action="store_true", default=argparse.SUPPRESS, help="Force live ARTEX verification")
    p_artex_loop.add_argument("--no-artex-live", action="store_true", default=argparse.SUPPRESS, help="Disable auto-live ARTEX verification")
    p_artex_loop.add_argument("--embedded-proxy", action="store_true", default=argparse.SUPPRESS, help="Start embedded recording MITM proxy")
    p_artex_loop.add_argument("--embedded-proxy-port", type=int, default=argparse.SUPPRESS, help="Embedded MITM proxy port")
    p_artex_loop.add_argument("--auth-profile", default=argparse.SUPPRESS, help="Auth profiles JSON/YAML path")
    p_artex_loop.add_argument("--import-har", default=argparse.SUPPRESS, help="Import HAR 1.2 file into AssetGraph")
    p_artex_loop.add_argument("--import-openapi", default=argparse.SUPPRESS, help="Import OpenAPI/Swagger spec into AssetGraph")
    p_artex_loop.add_argument("--scope-file", default=argparse.SUPPRESS, help="Scope allow/deny YAML/JSON file")
    p_artex_loop.add_argument("--approval-mode", choices=["policy", "prompt", "deny"], default=argparse.SUPPRESS, help="Approval gate mode")
    p_artex_loop.add_argument("--approval-rules", default=argparse.SUPPRESS, help="Approval rules YAML/JSON file")
    p_artex_loop.add_argument("--strict-poe", action="store_true", default=argparse.SUPPRESS, help="Enforce strict POE>=2")
    p_artex_loop.add_argument("--export-advisory", action="store_true", default=argparse.SUPPRESS, help="Export GHSA Markdown advisories")
    p_artex_loop.add_argument("--export-csv", action="store_true", default=argparse.SUPPRESS, help="Export formula-safe CSV")
    p_artex_loop.add_argument("--output-dir", default=argparse.SUPPRESS, help="Report output directory")
    p_artex_loop.add_argument("--json", dest="as_json", action="store_true", default=argparse.SUPPRESS, help="Emit JSON output")
    p_artex_loop.add_argument("--plain", action="store_true", default=argparse.SUPPRESS, help="Plain ASCII output")

    p_scanner = subparsers.add_parser("scanner", help="Run opt-in external scanners (httpx, katana, nuclei) into AssetGraph & DualGraph")
    p_scanner.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")
    p_scanner.add_argument("--host", "--target", dest="host", default=argparse.SUPPRESS, help="Target host (domain or IP)")
    p_scanner.add_argument("--port", type=int, default=argparse.SUPPRESS, action=_TrackExplicitStore, help="Target port")
    p_scanner.add_argument("--tls", action="store_true", default=argparse.SUPPRESS, help="Enable TLS/HTTPS")
    p_scanner.add_argument("--authorized", action="store_true", default=argparse.SUPPRESS, help="Explicitly authorize remote target")
    p_scanner.add_argument("--enable-external-scanners", dest="enable_external_scanners", action="store_true", default=argparse.SUPPRESS, help="Opt-in to external black-box scanners (httpx, katana, nuclei)")
    p_scanner.add_argument("--httpx-scan", dest="httpx_scan", action="store_true", default=argparse.SUPPRESS, help="Opt-in to ProjectDiscovery httpx discovery")
    p_scanner.add_argument("--katana-scan", dest="katana_scan", action="store_true", default=argparse.SUPPRESS, help="Opt-in to ProjectDiscovery katana crawling")
    p_scanner.add_argument("--nuclei-scan", dest="nuclei_scan", action="store_true", default=argparse.SUPPRESS, help="Opt-in to ProjectDiscovery nuclei non-destructive scanning")
    p_scanner.add_argument("--nuclei-tags", dest="nuclei_tags", type=str, default=argparse.SUPPRESS, help="Comma-separated non-destructive nuclei tags")
    p_scanner.add_argument("--scanner-isolation", dest="scanner_isolation", choices=["host", "docker"], default=argparse.SUPPRESS, help="External scanner isolation mode (host|docker)")
    p_scanner.add_argument("--docker-image", dest="docker_image", type=str, default=argparse.SUPPRESS, help="Optional explicit OCI image for docker isolation")
    p_scanner.add_argument("--docker-network", dest="docker_network", choices=["bridge", "none"], default=argparse.SUPPRESS, help="Docker network mode for external scanner isolation (bridge|none)")
    p_scanner.add_argument("--artex-noise-profile", choices=["off", "quiet", "balanced", "aggressive"], default=argparse.SUPPRESS, help="Noise governor profile")
    p_scanner.add_argument("--approval-mode", choices=["policy", "prompt", "deny"], default=argparse.SUPPRESS, help="Approval gate mode")
    p_scanner.add_argument("--approval-rules", default=argparse.SUPPRESS, help="Approval rules YAML/JSON file")
    p_scanner.add_argument("--scope-file", default=argparse.SUPPRESS, help="Scope allow/deny YAML/JSON file")
    p_scanner.add_argument("--output-dir", default=argparse.SUPPRESS, help="Report output directory")
    p_scanner.add_argument("--json", dest="as_json", action="store_true", default=argparse.SUPPRESS, help="Emit JSON output")
    p_scanner.add_argument("--plain", action="store_true", default=argparse.SUPPRESS, help="Plain ASCII output")

    # Pure-CLI Subcommands (Pillars 2, 5, 6 — zero GUI)
    p_proxy = subparsers.add_parser("proxy", help="Start embedded pure-CLI recording HTTP/HTTPS MITM proxy")
    p_proxy.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")
    p_proxy.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    p_proxy.add_argument("--port", type=int, default=8788, help="Bind port (default: 8788)")
    p_proxy.add_argument("--ca-dir", default="keys", help="Directory for auto-generated local CA cert/key")
    p_proxy.add_argument("--task-id", default=None, help="Task ID for recorded traffic")
    p_proxy.add_argument("--noise-profile", choices=["off", "quiet", "balanced", "aggressive"], default=None, help="Noise governor profile")
    p_proxy.add_argument("--rewrite-rule", action="append", default=[], help="Header rewrite rule (name:Header=Value)")
    p_proxy.add_argument("--authorized", action="store_true", default=False, help="Authorize forwarding to non-loopback hosts")
    p_proxy.add_argument("--duration", type=float, default=None, help="Optional run duration in seconds before clean shutdown")
    p_proxy.add_argument("--json", dest="as_json", action="store_true", default=argparse.SUPPRESS, help="Emit JSON output")
    p_proxy.add_argument("--plain", action="store_true", default=argparse.SUPPRESS, help="Plain ASCII output")

    p_chains = subparsers.add_parser("chains", help="List persisted ARTEX attack chains")
    p_chains.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")
    p_chains.add_argument("--task-id", default=None, help="Filter by task ID")
    p_chains.add_argument("--min-poe", type=int, default=0, help="Minimum POE level (0..3)")
    p_chains.add_argument("--verified-only", action="store_true", default=False, help="Show only verified chains")
    p_chains.add_argument("--limit", type=int, default=50, help="Maximum rows")
    p_chains.add_argument("--json", dest="as_json", action="store_true", default=argparse.SUPPRESS, help="Emit JSON output")
    p_chains.add_argument("--plain", action="store_true", default=argparse.SUPPRESS, help="Plain ASCII output")

    p_traces = subparsers.add_parser("traces", help="Search persisted ARTEX shared worker traces")
    p_traces.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")
    p_traces.add_argument("--task-id", default=None, help="Filter by task ID")
    p_traces.add_argument("--worker-id", default=None, help="Filter by worker ID")
    p_traces.add_argument("--query", "-q", default=None, help="Case-insensitive search substring")
    p_traces.add_argument("--limit", type=int, default=100, help="Maximum rows")
    p_traces.add_argument("--json", dest="as_json", action="store_true", default=argparse.SUPPRESS, help="Emit JSON output")
    p_traces.add_argument("--plain", action="store_true", default=argparse.SUPPRESS, help="Plain ASCII output")

    p_cov = subparsers.add_parser("coverage", help="Display ARTEX Asset Coverage Ledger from DB")
    p_cov.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")
    p_cov.add_argument("--task-id", default=None, help="Task ID")
    p_cov.add_argument("--json", dest="as_json", action="store_true", default=argparse.SUPPRESS, help="Emit JSON output")
    p_cov.add_argument("--plain", action="store_true", default=argparse.SUPPRESS, help="Plain ASCII output")

    p_retest = subparsers.add_parser("retest", help="Replay persisted attack chains and verify fixes")
    p_retest.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")
    p_retest.add_argument("--chain-id", default=None, help="Specific chain ID to retest")
    p_retest.add_argument("--task-id", default=None, help="Filter chains by task ID")
    p_retest.add_argument("--host", "--target", dest="host", default=None, help="Target host override for live retest")
    p_retest.add_argument("--port", type=int, default=None, help="Target port override for live retest")
    p_retest.add_argument("--tls", action="store_true", default=None, help="Enable TLS/HTTPS for live retest")
    p_retest.add_argument("--all-chains", action="store_true", default=False, help="Retest all persisted chains")
    p_retest.add_argument("--live", action="store_true", default=False, help="Send live HTTP replay requests via captured traffic")
    p_retest.add_argument("--authorized", action="store_true", default=False, help="Authorize live replay to non-loopback hosts")
    p_retest.add_argument("--limit", type=int, default=50, help="Maximum chains")
    p_retest.add_argument("--json", dest="as_json", action="store_true", default=argparse.SUPPRESS, help="Emit JSON output")
    p_retest.add_argument("--plain", action="store_true", default=argparse.SUPPRESS, help="Plain ASCII output")

    p_exp = subparsers.add_parser("export-advisory", help="Export GHSA-ready Markdown advisories and formula-safe CSV")
    p_exp.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")
    p_exp.add_argument("--chain-id", default=None, help="Specific chain ID to export")
    p_exp.add_argument("--task-id", default=None, help="Filter by task ID")
    p_exp.add_argument("--out", default="reports", help="Output directory")
    p_exp.add_argument("--csv", action="store_true", default=False, help="Also export formula-neutralized CSV")
    p_exp.add_argument("--limit", type=int, default=50, help="Maximum chains")
    p_exp.add_argument("--json", dest="as_json", action="store_true", default=argparse.SUPPRESS, help="Emit JSON output")
    p_exp.add_argument("--plain", action="store_true", default=argparse.SUPPRESS, help="Plain ASCII output")

    p_arch = subparsers.add_parser("archive", help="Export or verify AES-256-GCM encrypted task archives (*.rfca)")
    p_arch.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")
    p_arch.add_argument("--export", dest="export_path", default=None, help="Output encrypted archive file path (.rfca)")
    p_arch.add_argument("--import", dest="import_path", default=None, help="Input encrypted archive file path (.rfca) to decrypt and verify")
    p_arch.add_argument("--task-id", default=None, help="Optional task ID filter for export")
    p_arch.add_argument("--key-file", default=None, help="Optional encryption key file path")
    p_arch.add_argument("--json", dest="as_json", action="store_true", default=argparse.SUPPRESS, help="Emit JSON output")
    p_arch.add_argument("--plain", action="store_true", default=argparse.SUPPRESS, help="Plain ASCII output")

    p_mantis = subparsers.add_parser("mantis", help="Run Google Mantis (Module 20) security pipeline")
    p_mantis.add_argument("--repo", default=argparse.SUPPRESS, help="Repository directory path")
    p_mantis.add_argument("--path", default=argparse.SUPPRESS, help="File or directory path")
    p_mantis.add_argument("--depth", type=int, default=None, help="Mantis depth (1..100, default: 30)")
    p_mantis.add_argument("--mantis-mode", choices=["full", "fast", "threat-model", "scan", "reproduce", "patch"], default=argparse.SUPPRESS, help="Mantis mode")
    p_mantis.add_argument("--output-dir", default=argparse.SUPPRESS, help="Report output directory")

    p_rea = subparsers.add_parser("rea", help="Run Module 21 (morluto/rea) JS/Electron/.asar/source-map & same-origin bundle surface analyzer")
    p_rea.add_argument("--db", default=argparse.SUPPRESS, help="SQLite database path")
    p_rea.add_argument("--path", default=argparse.SUPPRESS, help="Target JS/Electron/.asar/map/HTML file or directory")
    p_rea.add_argument("--repo", default=argparse.SUPPRESS, help="Repository directory path")
    p_rea.add_argument("--rea-target", dest="rea_target", default=argparse.SUPPRESS, help="Target artifact path")
    p_rea.add_argument("--rea-cli", dest="rea_cli", action="store_true", default=argparse.SUPPRESS, help="Opt-in to locally installed rea-agents CLI (shell=False)")
    p_rea.add_argument("--host", "--target", dest="host", default=argparse.SUPPRESS, help="Authorized live host for same-origin JS bundle mining")
    p_rea.add_argument("--port", type=int, default=argparse.SUPPRESS, action=_TrackExplicitStore, help="Target port")
    p_rea.add_argument("--tls", action="store_true", default=argparse.SUPPRESS, help="Enable TLS/HTTPS")
    p_rea.add_argument("--authorized", action="store_true", default=argparse.SUPPRESS, help="Explicitly authorize remote host")
    p_rea.add_argument("--approval-mode", choices=["policy", "prompt", "deny"], default=argparse.SUPPRESS, help="Approval gate mode")
    p_rea.add_argument("--approval-rules", default=argparse.SUPPRESS, help="Approval rules YAML/JSON file")
    p_rea.add_argument("--artex-noise-profile", choices=["off", "quiet", "balanced", "aggressive"], default=argparse.SUPPRESS, help="Noise governor profile")
    p_rea.add_argument("--output-dir", default=argparse.SUPPRESS, help="Report output directory")
    p_rea.add_argument("--json", dest="as_json", action="store_true", default=argparse.SUPPRESS, help="Emit JSON output")
    p_rea.add_argument("--plain", action="store_true", default=argparse.SUPPRESS, help="Plain ASCII output")

    # Build All Pipeline
    p_build = subparsers.add_parser("build", help="Build all components, verify database, pre-cache RFCs, and run verification suite")
    p_build.add_argument("--skip-tests", action="store_true", help="Skip running the pytest verification suite")

    args = parser.parse_args()
    if not hasattr(args, "_explicit_cli_dests"):
        args._explicit_cli_dests = set()
    _explicit_dests = args._explicit_cli_dests
    if args.command in ("artex", "chain"):
        if "port" not in _explicit_dests:
            args.port = 8080
        if "artex_rounds" not in _explicit_dests:
            args.artex_rounds = 2
    elif args.command == "artex-loop":
        if "port" not in _explicit_dests:
            args.port = 8080
        if "artex_rounds" not in _explicit_dests:
            args.artex_rounds = 1

    from engine.execution_policy import ExecutionPolicy
    ExecutionPolicy.get_instance().allow_destructive = ExecutionPolicy.get_instance().allow_destructive or bool(getattr(args, "allow_destructive", False))

    is_mandatory_fusion = bool(
        getattr(args, "run_all_scans", False)
        or getattr(args, "mantis", False)
        or args.command in ("all", "mantis")
    )
    if is_mandatory_fusion:
        args.fusion = True
        args.abliteration = True
        if getattr(args, "model", None) in (None, "", "auto", "gemma2:2b"):
            args.model = "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"
    elif getattr(args, "abliteration", True):
        args.abliteration = True
        if getattr(args, "model", None) in (None, "", "auto", "gemma2:2b"):
            args.model = "hf.co/OBLITERATUS/Gemma-4-12B-OBLITERATED:Q4_K_M"

    if getattr(args, "clean_db", False):
        db = Database(args.db)
        try:
            res = db.clean_db(
                keep_rfcs=getattr(args, "keep_rfcs_on_clean", False),
                keep_findings=getattr(args, "keep_findings_on_clean", False),
                vacuum=True,
            )
        finally:
            db.close()
        print(
            f"[+] Database cleaned and VACUUMed: {res['total_rows_deleted']:,} rows removed, {res['reclaimed_mb']} MB reclaimed.",
            file=(sys.stderr if getattr(args, "as_json", False) else sys.stdout),
        )
        if not args.command and not getattr(args, "run_all_scans", False) and not getattr(args, "mantis", False):
            sys.exit(0)

    if getattr(args, "run_all_scans", False) and not args.command:
        cmd_all(args)
        return

    if getattr(args, "mantis", False) and not args.command:
        cmd_mantis(args)
        return

    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "all": cmd_all,
        "artex": cmd_artex,
        "artex-loop": cmd_artex_loop,
        "chain": cmd_artex,
        "scanner": cmd_scanner,
        "proxy": cmd_proxy,
        "chains": cmd_chains,
        "traces": cmd_traces,
        "coverage": cmd_coverage,
        "retest": cmd_retest,
        "export-advisory": cmd_export_advisory,
        "archive": cmd_archive,
        "mantis": cmd_mantis,
        "rea": cmd_rea,
        "build": cmd_build,
        "ruler": cmd_ruler,
        "hunt": cmd_hunt,
        "mcp": cmd_mcp,
        "fetch": cmd_fetch,
        "chunk": cmd_chunk,
        "generate": cmd_generate,
        "permute": cmd_permute,
        "evaluate": cmd_evaluate,
        "weaponize": cmd_weaponize,
        "cascade": cmd_cascade,
        "lab": cmd_lab,
        "auto": cmd_auto,
        "dream": cmd_dream,
        "caldera": cmd_caldera,
        "harness2": cmd_harness2,
    }

    dispatch[args.command](args)


if __name__ == "__main__":
    main()
