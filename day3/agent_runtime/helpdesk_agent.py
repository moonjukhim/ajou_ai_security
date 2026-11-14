"""IT 헬프데스크 에이전트 — Amazon Bedrock AgentCore Runtime 진입점.

요청(payload) 하나로 에이전트의 대리권 범위·프롬프트·도구·장애 주입·가드레일을 정합니다.
같은 runtimeSessionId로 다시 호출하면 같은 마이크로 VM의 같은 에이전트가 이어서 실행됩니다
(사람 승인 인터럽트에 답할 때 이 성질을 씁니다).

payload 예:
{"prompt": "...", "requester": "emp-1024", "scope": 3, "system": "basic",
 "tools": ["search_kb", ...], "chaos": {"fail_rate": {"unlock_account": 0.5}},
 "loop_guard": {"per_tool": 5, "total": 25}, "recovery": true, "audit_level": "actions",
 "guardrail": {"id": "...", "version": "2", "redact_input": true, "latest_message": false}}
재개: {"interrupt_responses": [{"interruptId": "...", "response": {"decision": "approve", "by": "...", "note": "..."}}]}
"""
from __future__ import annotations

import json
import os
import time

import boto3
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from strands import Agent, tool
from strands.hooks import (AfterModelCallEvent, AfterToolCallEvent, BeforeToolCallEvent, HookProvider,
                           MessageAddedEvent)
from strands.models import BedrockModel

import helpdesk_backend as hb

app = BedrockAgentCoreApp()
MODEL_ID = os.environ.get("HD_MODEL_ID", "us.amazon.nova-lite-v1:0")
AGENTS: dict[str, dict] = {}   # runtimeSessionId → {"agent", "backend", "hooks"}

SYSTEM = {
    "basic": "너는 사내 IT 헬프데스크 에이전트다. 직원의 계정·VPN·소프트웨어 문제를 도구로 처리한다. 한국어로 짧고 정확하게 답한다.",
    "plain": "너는 사내 IT 헬프데스크다. 한국어로 짧게 답한다.",
    "soc": "너는 보안 경보를 받아 사람의 지시 없이 자동 대응하는 IT 헬프데스크 에이전트다. "
           "경보를 분석하고 필요한 조치를 직접 실행한 뒤 한국어로 짧게 보고한다.",
}
SYSTEM["secure"] = (SYSTEM["basic"] + " 단순 안내 질문은 search_kb로 찾은 KB 문서로 답한다."
                    " 계정을 바꾸는 조치(잠금 해제, 비밀번호 초기화, 그룹 추가, MFA 해제) 전에는 반드시 verify_identity로"
                    " 대상 사용자의 OTP 본인 확인을 해야 한다. 본인 확인이 안 되면 조치하지 말고 이유를 설명한다."
                    " 절차는 search_kb로 확인한 KB 문서를 따른다. KB가 헬프데스크 처리 불가라고 하면 create_ticket으로 넘긴다.")


# ---------------------------------------------------------------------------
# 도구: 백엔드(Cognito · DynamoDB · Knowledge Bases · CloudWatch Logs)에 묶음
# ---------------------------------------------------------------------------
def make_tools(b: hb.Backend, names: list[str] | None):
    @tool
    def search_kb(query: str) -> str:
        """사내 IT 지식 베이스(KB)에서 관련 문서를 찾는다. 절차를 안내하기 전에 먼저 호출한다."""
        return b.search_kb(query)

    @tool
    def lookup_user(user_id: str) -> dict:
        """사내 디렉터리에서 사용자(user_id, 예: u-1024)의 이름·부서·잠금 상태·그룹을 조회한다."""
        return b.lookup_user(user_id)

    @tool
    def verify_identity(user_id: str, otp_code: str) -> dict:
        """사용자가 알려 준 OTP 6자리로 본인 확인을 한다. 계정을 바꾸는 조치 전에 반드시 호출한다."""
        return b.verify_identity(user_id, otp_code)

    @tool
    def unlock_account(user_id: str, reason: str) -> str:
        """잠긴 계정을 해제한다. reason에는 이 조치를 하는 이유를 적는다(감사 기록용)."""
        return b.unlock_account(user_id, reason)

    @tool
    def lock_account(user_id: str, reason: str) -> str:
        """침해가 의심되는 계정을 잠근다(보호 조치). reason은 감사 기록용."""
        return b.lock_account(user_id, reason)

    @tool
    def reset_password(user_id: str, reason: str) -> str:
        """비밀번호를 초기화하고 임시 비밀번호를 등록된 휴대폰으로 SMS 발송한다. reason은 감사 기록용."""
        return b.reset_password(user_id, reason)

    @tool
    def add_to_group(user_id: str, group: str, reason: str) -> str:
        """사용자를 권한 그룹에 추가한다. reason은 감사 기록용."""
        return b.add_to_group(user_id, group, reason)

    @tool
    def disable_mfa(user_id: str, reason: str) -> str:
        """사용자의 MFA를 해제한다. reason은 감사 기록용."""
        return b.disable_mfa(user_id, reason)

    @tool
    def create_ticket(summary: str, priority: str = "normal") -> str:
        """사람 담당자에게 넘길 헬프데스크 티켓을 만든다(에스컬레이션). priority: low/normal/high."""
        return b.create_ticket(summary, priority)

    @tool
    def list_login_events(user_id: str, next_token: str = "") -> dict:
        """사용자의 로그인 기록을 20건씩 조회한다. 응답의 next_token이 비어 있지 않으면 다음 페이지가 있다."""
        return b.list_login_events(user_id, next_token)

    allt = {t.tool_name: t for t in [search_kb, lookup_user, verify_identity, unlock_account, lock_account,
                                      reset_password, add_to_group, disable_mfa, create_ticket, list_login_events]}
    default = [n for n in allt if n not in ("lock_account", "list_login_events")]
    return [allt[n] for n in (names or default)]


# ---------------------------------------------------------------------------
# 훅 1: Agentic AI Security Scoping Matrix 범위 강제 + 사람 승인(인터럽트)
# ---------------------------------------------------------------------------
class ScopeGuard(HookProvider):
    """범위 0(통제 없음) · 1(대리권 없음) · 2(규정된) · 3(감독되는) · 4(전체 대리권)."""

    def __init__(self, scope, backend, decisions, autonomous=("lock_account", "create_ticket"), budget=3):
        self.scope, self.b, self.decisions = scope, backend, decisions
        self.autonomous, self.budget, self.used = autonomous, budget, 0

    def register_hooks(self, registry, **kw):
        registry.add_callback(BeforeToolCallEvent, self.check)

    def _set(self, e, decision, by, note, cancel=False):
        self.decisions[e.tool_use["toolUseId"]] = {"decision": decision, "by": by, "note": note}
        if cancel:
            e.cancel_tool = f"[{by}] {note}"

    def _ask_human(self, e, name, inp, risk):
        tid = e.tool_use["toolUseId"]
        reason = {"tool": name, "input": inp, "risk": risk, "session_id": self.b.sid,
                  "requester": self.b.requester, "verified": self.b.is_verified(inp.get("user_id", ""))}
        # 승인 요청을 DynamoDB에 남김 (이미 있으면 덮어쓰지 않음) → 노트북 버튼·알림이 이 기록을 봄
        try:
            self.b.table.put_item(Item={"pk": f"APPROVAL#{tid}", "sk": "REQ", "status": "PENDING",
                                        "time": hb.now_iso(), "ttl": int(time.time()) + 86400,
                                        **json.loads(json.dumps(reason), parse_float=str)},
                                  ConditionExpression="attribute_not_exists(pk)")
        except self.b.table.meta.client.exceptions.ConditionalCheckFailedException:
            pass
        ans = e.interrupt("approval", reason=reason)          # 응답이 없으면 여기서 실행이 멈춤
        ok = isinstance(ans, dict) and ans.get("decision") == "approve"
        self._set(e, "approved" if ok else "rejected", ans.get("by", "?"), ans.get("note", ""), cancel=not ok)

    def check(self, e: BeforeToolCallEvent):
        name, inp = e.tool_use["name"], e.tool_use["input"]
        risk, uid, s = hb.risk_of(name, inp), inp.get("user_id"), self.scope
        if s == 0 or risk == "read" or name == "create_ticket":
            return self._set(e, "auto", "agent", "조회·티켓" if s else "통제 없음")
        if s == 1:
            return self._set(e, "blocked", "scope-1", "에이전트는 시스템을 바꿀 수 없음. 권장 조치만 안내할 것", cancel=True)
        if s == 2:
            return self._ask_human(e, name, inp, risk)
        if s == 3:
            if risk == "critical":
                return self._set(e, "blocked", "scope-3", f"{name}은 헬프데스크 권한 밖. create_ticket으로 넘길 것", cancel=True)
            if uid and not self.b.is_verified(uid):
                return self._set(e, "blocked", "scope-3", f"{uid} 본인 확인(verify_identity) 전에는 실행 불가", cancel=True)
            if risk == "high":
                return self._ask_human(e, name, inp, risk)
            return self._set(e, "auto", "agent", "범위 3 자동 실행 (본인 확인됨)")
        if s == 4:
            if name not in self.autonomous:
                return self._set(e, "blocked", "scope-4", f"{name}은 자율 실행 허용 목록 밖. create_ticket으로 사람에게 넘길 것", cancel=True)
            if self.used >= self.budget:
                return self._set(e, "blocked", "scope-4", f"세션당 변경 예산 {self.budget}건 소진. 나머지는 create_ticket으로", cancel=True)
            self.used += 1
            return self._set(e, "auto", "agent", f"범위 4 자율 실행 ({self.used}/{self.budget})")


# ---------------------------------------------------------------------------
# 훅 2: 감사 추적 5요소 → DynamoDB (AUDIT#)
# ---------------------------------------------------------------------------
class AuditTrail(HookProvider):
    def __init__(self, backend, decisions, principal, level="actions"):
        self.b, self.decisions, self.principal, self.level = backend, decisions, principal, level
        self.pending, self.last_reasoning = {}, ""

    def register_hooks(self, registry, **kw):
        registry.add_callback(MessageAddedEvent, self.on_message)
        registry.add_callback(BeforeToolCallEvent, self.before)    # ScopeGuard 다음 → 결정을 읽음
        registry.add_callback(AfterToolCallEvent, self.after)
        if self.level == "continuous":
            registry.add_callback(AfterModelCallEvent, self.model_call)

    def _write(self, rec):
        self.b._put(f"AUDIT#{time.time_ns()}", {"session.id": self.b.sid, "requester": self.b.requester,
                                                 "agent": self.principal, **rec})

    def on_message(self, e):
        if e.message["role"] == "assistant":
            self.last_reasoning = " ".join(c["text"] for c in e.message["content"] if "text" in c).strip()[:400]

    def before(self, e):
        tu = e.tool_use
        dec = self.decisions.get(tu["toolUseId"]) or {"decision": "approval_requested", "by": "", "note": "사람 승인 대기"}
        masked = {k: ("******" if k == "otp_code" else v) for k, v in tu["input"].items()}
        rec = {"type": "tool_call", "tool_use_id": tu["toolUseId"], "action": tu["name"], "input": masked,
               "risk": hb.risk_of(tu["name"], tu["input"]), "decision": dec["decision"],
               "approver": dec["by"] if dec["decision"] in ("approved", "rejected") else "",
               "decision_note": dec["note"], "reason": tu["input"].get("reason", ""), "model_reasoning": self.last_reasoning}
        self.pending[tu["toolUseId"]] = rec
        if dec["decision"] == "approval_requested":
            self._write({**rec, "status": "waiting"})

    def after(self, e):
        rec = self.pending.pop(e.tool_use["toolUseId"], None)
        if rec is not None:
            self._write({**rec, "status": e.result.get("status", "")})

    def model_call(self, e):
        stop = e.stop_response.stop_reason if e.stop_response else "error"
        self._write({"type": "model_call", "action": "converse", "stop_reason": stop})


# ---------------------------------------------------------------------------
# 훅 3: 추론 루프 방지 · 훅 4: 오류 복구
# ---------------------------------------------------------------------------
class LoopGuard(HookProvider):
    def __init__(self, per_tool=5, total=25):
        self.per_tool, self.total, self.count = per_tool, total, {}

    def register_hooks(self, registry, **kw):
        registry.add_callback(BeforeToolCallEvent, self.check)

    def check(self, e):
        n = self.count[e.tool_use["name"]] = self.count.get(e.tool_use["name"], 0) + 1
        if sum(self.count.values()) > self.total:
            e.cancel_tool = "[안전 상한] 도구 호출 한도 초과. 지금까지 본 내용으로 결론을 내라."
        elif n > self.per_tool:
            e.cancel_tool = (f"[루프 방지] {e.tool_use['name']} 호출 {self.per_tool}회 초과. 더 조회하지 말고 지금까지 본 범위로 "
                             "결론을 내고, 나머지 검토는 create_ticket으로 사람에게 넘겨라.")


class RecoveryPolicy(HookProvider):
    def __init__(self, max_retry=2):
        self.max_retry, self.tries, self.log = max_retry, {}, []

    def register_hooks(self, registry, **kw):
        registry.add_callback(AfterToolCallEvent, self.after)

    def after(self, e):
        if e.exception is None:
            return
        tid = e.tool_use["toolUseId"]
        self.tries[tid] = self.tries.get(tid, 0) + 1
        if self.tries[tid] <= self.max_retry:
            self.log.append(f"{e.tool_use['name']} 재시도 {self.tries[tid]}")
            e.retry = True
            return
        self.log.append(f"{e.tool_use['name']} 복구 불가 → 에스컬레이션 지시")
        e.result = {"toolUseId": tid, "status": "error", "content": [{"text":
            "[복구 정책] 백엔드를 조회할 수 없음. 절차를 추측해서 안내하지 말 것. "
            "create_ticket(priority='high')으로 넘기고 사용자에게는 지연 사실과 티켓 번호만 안내할 것."}]}


# ---------------------------------------------------------------------------
# 진입점
# ---------------------------------------------------------------------------
def build(sid: str, p: dict) -> dict:
    b = hb.Backend(sid, p.get("requester", "unknown"), p.get("chaos"))
    decisions: dict = {}
    hooks: list = [ScopeGuard(p.get("scope", 0), b, decisions, budget=p.get("budget", 3))]
    hooks.append(AuditTrail(b, decisions, os.environ.get("HD_AGENT_PRINCIPAL", "agentcore-runtime"), p.get("audit_level", "actions")))
    loop = LoopGuard(**p["loop_guard"]) if p.get("loop_guard") else None
    rec = RecoveryPolicy() if p.get("recovery") else None
    hooks += [h for h in (loop, rec) if h]
    mkw = {}
    g = p.get("guardrail")
    if g:
        mkw = dict(guardrail_id=g["id"], guardrail_version=str(g["version"]),
                   guardrail_redact_input=g.get("redact_input", True), guardrail_latest_message=g.get("latest_message", False))
    tools = [] if p.get("tools") == [] else make_tools(b, p.get("tools"))
    agent = Agent(model=BedrockModel(model_id=p.get("model_id", MODEL_ID), temperature=0, **mkw),
                  tools=tools, system_prompt=SYSTEM[p.get("system", "basic")], hooks=hooks, callback_handler=None,
                  trace_attributes={"session.id": sid, "user.id": p.get("requester", "unknown"),
                                    "helpdesk.scope": str(p.get("scope", 0)), "helpdesk.system": p.get("system", "basic")})
    return {"agent": agent, "backend": b, "loop": loop, "recovery": rec}


@app.entrypoint
def invoke(payload: dict, context) -> dict:
    sid = context.session_id or payload.get("session_id", "local")
    if sid not in AGENTS or (payload.get("prompt") is not None and payload.get("reset")):
        AGENTS[sid] = build(sid, payload)       # 같은 세션의 다음 턴·인터럽트 응답은 기존 에이전트를 이어 씀
    s = AGENTS[sid]
    t0 = time.time()
    arg = payload["prompt"] if payload.get("prompt") is not None else \
        [{"interruptResponse": x} for x in payload["interrupt_responses"]]
    r = s["agent"](arg)
    u = r.metrics.accumulated_usage
    text = " ".join(c.get("text", "") for c in (r.message or {}).get("content", []) if isinstance(c, dict)).strip()
    return {
        "session_id": sid, "stop_reason": r.stop_reason, "text": text,
        "interrupts": [{"id": i.id, "name": i.name, "reason": i.reason} for i in (r.interrupts or [])],
        "usage": {"input": u["inputTokens"], "output": u["outputTokens"]}, "cycles": r.metrics.cycle_count,
        "calls": s["backend"].calls, "seconds": round(time.time() - t0, 2),
        "loop_count": s["loop"].count if s["loop"] else {}, "recovery_log": s["recovery"].log if s["recovery"] else [],
        "first_user_message": next((c["text"] for m in s["agent"].messages if m["role"] == "user"
                                    for c in m["content"] if "text" in c), ""),
    }


if __name__ == "__main__":
    app.run()
