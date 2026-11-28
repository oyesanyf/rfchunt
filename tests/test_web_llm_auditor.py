"""
Unit Tests for Module 25 (Web LLM Defensive Security Auditor) and MCP Tool Wiring.
"""

from pathlib import Path
from engine.web_llm_auditor import audit_web_llm_repository


def test_web_llm_auditor_detects_all_seven_vulnerability_classes(tmp_path: Path):
    vuln_py = tmp_path / "llm_app.py"
    vuln_py.write_text(
        '''
from fastapi import FastAPI
app = FastAPI()

SYSTEM_PROMPT = "You are a helper. Only allow admins to delete accounts and never reveal other users' data."

tools = [delete_user, execute_sql]

def handle_tool(tool_call):
    args = tool_call.function.arguments
    cursor.execute("DELETE FROM users WHERE id = " + args)

def build_prompt(retrieved_chunks):
    return [{"role": "user", "content": f"Context: {retrieved_chunks}"}]

def query_rag(q):
    docs = vector_store.query(q)
    return docs

@app.post("/rag/upload")
def upload_doc(doc: str):
    return {"ok": True}
''',
        encoding="utf-8",
    )

    vuln_tsx = tmp_path / "ChatView.tsx"
    vuln_tsx.write_text(
        '''
export function ChatView({ resp }: any) {
  const html = resp.choices[0].message.content;
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
''',
        encoding="utf-8",
    )

    rep = audit_web_llm_repository(tmp_path)
    assert rep.files_scanned == 2
    rule_ids = {f.rule_id for f in rep.findings}
    assert "WEBLLM-AGENCY-001" in rule_ids
    assert "WEBLLM-TAINT-002" in rule_ids
    assert "WEBLLM-OUTPUT-003" in rule_ids
    assert "WEBLLM-FENCE-004" in rule_ids
    assert "WEBLLM-PROMPT-AUTHZ-005" in rule_ids
    assert "WEBLLM-RAG-SCRUB-006" in rule_ids
    assert "WEBLLM-INGEST-007" in rule_ids
    assert rep.defensive_checklist["apis_independently_authorized"] is False
    assert rep.defensive_checklist["programmatic_authz_not_prompt_only"] is False
    assert rep.defensive_checklist["output_handling_sanitized"] is False


def test_web_llm_auditor_clean_hardened_repo_passes_checklist(tmp_path: Path):
    safe_py = tmp_path / "hardened_llm.py"
    safe_py.write_text(
        '''
from engine.execution_policy import sanitize_for_llm_prompt

@requires_auth
def handle_tool(current_user):
    require_confirmation(current_user)
    tools = [delete_user]
    return tools

def build_prompt(retrieved_chunks):
    safe_ctx = sanitize_for_llm_prompt(retrieved_chunks)
    return [{"role": "user", "content": safe_ctx}]

def query_rag(q, tenant_id):
    return vector_store.query(q, filter={"tenant_id": tenant_id})

def render_reply(llm_output):
    safe = html.escape(llm_output)
    return safe
''',
        encoding="utf-8",
    )

    rep = audit_web_llm_repository(tmp_path)
    assert rep.files_scanned == 1
    assert len(rep.findings) == 0
    assert all(rep.defensive_checklist.values())


def test_mcp_server_registers_module_24_and_25_tools(tmp_path: Path):
    import json
    from mcp_server import TerminatorMCPServer

    srv = TerminatorMCPServer(db_path=str(tmp_path / "test.db"))
    try:
        tools_resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
        assert "run_crlf_conformance_audit" in tool_names
        assert "run_web_llm_security_audit" in tool_names

        r24 = srv.handle_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "run_crlf_conformance_audit", "arguments": {"target_path": str(tmp_path)}},
        })
        res24 = json.loads(r24["result"]["content"][0]["text"])
        assert res24["module"] == "Module-24-CRLF-Conformance"

        r25 = srv.handle_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "run_web_llm_security_audit", "arguments": {"target_path": str(tmp_path)}},
        })
        res25 = json.loads(r25["result"]["content"][0]["text"])
        assert res25["module"] == "Module-25-Web-LLM-Auditor"
    finally:
        srv.db.close()
