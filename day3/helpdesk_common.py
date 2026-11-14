"""3회차 AWS 데모 노트북 공통 도우미 — 실제 AWS에 배포한 헬프데스크 에이전트를 다룬다.

00_setup_infrastructure.ipynb가 만든 lab_config.json을 읽어서
- AgentCore Runtime의 에이전트를 호출하고 (invoke / run_session: 사람 승인 인터럽트 처리 포함)
- DynamoDB에 남은 변경·티켓·감사·승인 기록을 읽고
- CloudWatch(aws/spans, 런타임 로그 그룹)에서 트레이스를 조회합니다.

노트북과 같은 폴더에 두고 `import helpdesk_common as H`로 씁니다.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from typing import Any, Callable

import boto3

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "agent_runtime"))
import lab_infra as L  # noqa: E402

CFG = L.load()
if not CFG.get("runtime_arn"):          # 설정 파일이 없거나 비었으면 이름 규칙으로 AWS에서 찾아 다시 만듦
    CFG = L.discover()
if not CFG.get("runtime_arn"):
    raise RuntimeError(f"리전 {L.REGION}에서 실습 런타임({L.PU}_helpdesk)을 찾지 못했습니다. "
                       "00_setup_infrastructure.ipynb를 같은 리전에서 끝까지 실행했는지 확인하세요. "
                       "(리전을 지정하려면 첫 셀에서 os.environ['AWS_REGION']을 설정하고 커널 재시작)")
for _k, _v in L.runtime_env().items():
    os.environ.setdefault(_k, _v)
import helpdesk_backend as hb  # noqa: E402

REGION = CFG["region"]
MODEL_ID = CFG.get("model_id", "us.amazon.nova-lite-v1:0")
PREFIX = f"ajou-aisec3x-{CFG['suffix']}"
RISK, risk_of = hb.RISK, hb.risk_of

from botocore.config import Config  # noqa: E402

# 에이전트 실행은 수십 초 걸릴 수 있음 → 읽기 시간 초과를 넉넉히, 같은 요청이 두 번 실행되지 않게 자동 재시도는 끔
_dp = boto3.client("bedrock-agentcore", region_name=REGION,
                   config=Config(read_timeout=900, connect_timeout=10, retries={"max_attempts": 1}))
_logs = boto3.client("logs", region_name=REGION)
_table = boto3.resource("dynamodb", region_name=REGION).Table(CFG["table"])


# ---------------------------------------------------------------------------
# 출력
# ---------------------------------------------------------------------------
def show(rows: list[dict], cols: list[str] | None = None, title: str | None = None, width: int = 60):
    import pandas as pd

    df = pd.DataFrame(rows)
    if cols:
        df = df[[c for c in cols if c in df.columns]]
    for c in df.columns:
        if df[c].dtype == object:
            df[c] = df[c].map(lambda v: _short(v, width))
    if title:
        print(f"■ {title}")
    with pd.option_context("display.max_colwidth", width + 5, "display.width", 250, "display.precision", 3):
        try:
            from IPython import get_ipython
            from IPython.display import HTML, display

            if get_ipython() is None:
                raise RuntimeError
            display(HTML(df.to_html(index=False, justify="left", escape=True)))
        except Exception:
            print(df.to_string(index=False))


def _short(v: Any, n: int) -> Any:
    if isinstance(v, (dict, list)):
        v = json.dumps(v, ensure_ascii=False)
    if isinstance(v, str):
        v = v.replace("\n", " ")
        return v if len(v) <= n else v[: n - 1] + "…"
    return v


def clean(text: Any) -> str:
    return re.sub(r"<thinking>.*?</thinking>", "", str(text), flags=re.S).strip()


def mask_account(s: str) -> str:
    return re.sub(r"\b(\d{8})(\d{4})\b", r"********\2", str(s))


def percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    v = sorted(values)
    k = (len(v) - 1) * p / 100
    f, c = int(k), min(int(k) + 1, len(v) - 1)
    return v[f] + (v[c] - v[f]) * (k - f)


# ---------------------------------------------------------------------------
# 준비 상태 확인
# ---------------------------------------------------------------------------
def check() -> None:
    arn = boto3.client("sts", region_name=REGION).get_caller_identity()["Arn"]
    rt = boto3.client("bedrock-agentcore-control", region_name=REGION).get_agent_runtime(agentRuntimeId=CFG["runtime_id"])
    print(f"자격 증명: {mask_account(arn)}")
    print(f"리전: {REGION} | 모델: {MODEL_ID}")
    print(f"AgentCore Runtime: {CFG['runtime_id']} (버전 {rt['agentRuntimeVersion']}, {rt['status']})")
    print(f"디렉터리: Cognito {CFG['user_pool_id']} | KB: {CFG['kb_id']} | 기록: DynamoDB {CFG['table']}")
    if rt["status"] != "READY":
        raise RuntimeError("런타임이 READY가 아닙니다. 00_setup 노트북의 배포 셀을 다시 실행하세요.")


# ---------------------------------------------------------------------------
# 직원 휴대폰(인증 앱) · 디렉터리
# ---------------------------------------------------------------------------
_SEEDS: dict | None = None


def otp(user_id: str) -> str | None:
    """직원 휴대폰의 인증 앱이 지금 보여 주는 6자리 (TOTP). 등록하지 않은 직원은 None."""
    global _SEEDS
    if _SEEDS is None:
        _SEEDS = json.loads(boto3.client("secretsmanager", region_name=REGION)
                            .get_secret_value(SecretId=CFG["totp_secret"])["SecretString"])
    return hb.totp(_SEEDS[user_id]) if user_id in _SEEDS else None


def reset_directory(users: list[str] | None = None) -> None:
    L.reset_directory(users)


def directory_state(user_id: str) -> dict:
    return hb.Backend("state-check-" + "0" * 30, "notebook").lookup_user(user_id)


# ---------------------------------------------------------------------------
# AgentCore Runtime 호출
# ---------------------------------------------------------------------------
def new_session_id(prefix: str = "sess") -> str:
    return f"{prefix}-{uuid.uuid4().hex}"          # runtimeSessionId는 33자 이상


def invoke(payload: dict, session_id: str) -> dict:
    for attempt in range(5):
        try:
            r = _dp.invoke_agent_runtime(agentRuntimeArn=CFG["runtime_arn"], runtimeSessionId=session_id,
                                         payload=json.dumps(payload, ensure_ascii=False).encode("utf-8"))
            out = json.loads(r["response"].read())
            if isinstance(out, dict) and out.get("error"):
                raise RuntimeError(out["error"])
            return out
        except (_dp.exceptions.ThrottlingException, _dp.exceptions.ServiceQuotaExceededException):
            time.sleep(3 * (attempt + 1))
    raise RuntimeError("런타임 호출이 계속 제한(throttling)되었습니다.")


def decide(tool_use_id: str, decision: str, by: str, note: str) -> dict:
    """승인 요청(DynamoDB APPROVAL#)에 사람의 결정을 기록하고 인터럽트 응답을 만든다."""
    _table.update_item(Key={"pk": f"APPROVAL#{tool_use_id}", "sk": "REQ"},
                       UpdateExpression="SET #s=:s, decided_by=:b, note=:n, decided_at=:t",
                       ExpressionAttributeNames={"#s": "status"},
                       ExpressionAttributeValues={":s": decision.upper(), ":b": by, ":n": note, ":t": hb.now_iso()})
    return {"decision": decision, "by": by, "note": note}


def tool_use_id_of(interrupt_id: str) -> str:
    # 인터럽트 ID 형식: v1:before_tool_call:<toolUseId>:<uuid>
    return interrupt_id.split(":")[2]


def run_session(payload: dict, session_id: str | None = None, reviewer: Callable | None = None) -> dict:
    """에이전트를 실행하고, 사람 승인 인터럽트가 나오면 reviewer(reason) → 결정을 DynamoDB에 기록한 뒤 이어서 실행."""
    sid = session_id or new_session_id()
    out = invoke({**payload, "reset": True}, sid)
    reviews = []
    while out["stop_reason"] == "interrupt":
        responses = []
        for it in out["interrupts"]:
            ans = reviewer(it["reason"]) if reviewer else {"decision": "reject", "by": "nobody", "note": "검토자 없음"}
            decide(tool_use_id_of(it["id"]), ans["decision"], ans["by"], ans["note"])
            reviews.append({**it["reason"], **ans})
            responses.append({"interruptId": it["id"], "response": ans})
        out = invoke({"interrupt_responses": responses}, sid)
    out["reviews"], out["session_id"] = reviews, sid
    return out


# ---------------------------------------------------------------------------
# DynamoDB 기록
# ---------------------------------------------------------------------------
def items(session_id: str, prefix: str = "") -> list[dict]:
    return hb.session_items(session_id, prefix)


def changes(session_id: str) -> list[dict]:
    return items(session_id, "CHANGE#")


def tickets(session_id: str) -> list[dict]:
    return items(session_id, "TICKET#")


def audit(session_id: str) -> list[dict]:
    return items(session_id, "AUDIT#")


def harmful(chs: list[dict]) -> list[dict]:
    return hb.harmful(chs)


def approval(tool_use_id: str) -> dict:
    return hb._clean(_table.get_item(Key={"pk": f"APPROVAL#{tool_use_id}", "sk": "REQ"}).get("Item", {}))


# ---------------------------------------------------------------------------
# CloudWatch: 트레이스(aws/spans)와 런타임 로그
# ---------------------------------------------------------------------------
def logs_query(group: str, query: str, minutes: int = 60) -> list[dict]:
    end = int(time.time())
    qid = _logs.start_query(logGroupName=group, startTime=end - minutes * 60, endTime=end + 60, queryString=query)["queryId"]
    while True:
        r = _logs.get_query_results(queryId=qid)
        if r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            return [{f["field"]: f["value"] for f in row if f["field"] != "@ptr"} for row in r["results"]]
        time.sleep(1)


def session_spans(session_ids: list[str] | str, minutes: int = 60) -> list[dict]:
    """aws/spans에서 세션의 스팬(원본 JSON)을 가져온다."""
    ids = [session_ids] if isinstance(session_ids, str) else session_ids
    quoted = ", ".join(f"'{s}'" for s in ids)
    rows = logs_query("aws/spans", f"fields @message | filter attributes.session.id in [{quoted}] | limit 10000", minutes)
    return [json.loads(r["@message"]) for r in rows]


def wait_for_spans(session_ids: list[str], timeout: int = 300, minutes: int = 60) -> list[dict]:
    """스팬이 CloudWatch에 들어올 때까지 기다린다 (보통 1~3분). 세션마다 invoke_agent 스팬이 있어야 완료."""
    t0 = time.time()
    while True:
        sp = session_spans(session_ids, minutes)
        have = {s.get("attributes", {}).get("session.id") for s in sp if s.get("name", "").startswith("invoke_agent")}
        if set(session_ids) <= have or time.time() - t0 > timeout:
            print(f"스팬 {len(sp)}개 수집 (세션 {len(have & set(session_ids))}/{len(session_ids)}, {time.time() - t0:.0f}초 대기)")
            return sp
        time.sleep(15)


def runtime_logs_for_traces(trace_ids: list[str], minutes: int = 60) -> list[dict]:
    """런타임 로그 그룹에서 트레이스의 대화 기록(OTel 로그: 입력·출력 메시지)을 가져온다."""
    if not trace_ids:
        return []
    quoted = ", ".join(f"'{t}'" for t in trace_ids)
    rows = logs_query(CFG["runtime_log_group"], f"fields @message | filter traceId in [{quoted}] | limit 10000", minutes)
    out = []
    for r in rows:
        try:
            out.append(json.loads(r["@message"]))
        except (json.JSONDecodeError, KeyError):
            pass
    return out


def eval_input(session_id: str, spans: list[dict], minutes: int = 60) -> list[dict]:
    """AgentCore Evaluations에 넘길 문서: Strands 스팬 + 대화 내용이 있는 런타임 로그."""
    mine = [s for s in spans if s.get("attributes", {}).get("session.id") == session_id]
    strands = [s for s in mine if s.get("scope", {}).get("name") in ("strands.telemetry.tracer", "strands-agents")]
    logs = [x for x in runtime_logs_for_traces(sorted({s["traceId"] for s in mine}), minutes)
            if isinstance(x.get("body"), dict) and ("input" in x["body"] or "output" in x["body"])]
    return strands + logs


def span_status(s: dict) -> str:
    return (s.get("status") or {}).get("code", "UNSET")


def print_span_tree(spans: list[dict]) -> None:
    """aws/spans 문서를 부모-자식으로 들여쓰기 (X-Ray 트레이스 맵을 글자로)."""
    by_parent: dict[str, list] = {}
    ids = {s["spanId"] for s in spans}
    for s in spans:
        p = s.get("parentSpanId") or ""
        by_parent.setdefault(p if p in ids else "", []).append(s)
    for v in by_parent.values():
        v.sort(key=lambda s: s.get("startTimeUnixNano", 0))

    def walk(s, depth):
        a = s.get("attributes", {})
        extra = []
        if "gen_ai.usage.input_tokens" in a:
            extra.append(f"토큰 {a['gen_ai.usage.input_tokens']}→{a.get('gen_ai.usage.output_tokens')}")
        if span_status(s) == "ERROR":
            extra.append("❌ " + str((s.get("status") or {}).get("message", "ERROR"))[:60])
        dur = (s.get("durationNano") or (s.get("endTimeUnixNano", 0) - s.get("startTimeUnixNano", 0))) / 1e9
        print(f"{'   ' * depth}└ {s['name'][:40]:<40} {dur:5.2f}s  [{s.get('scope', {}).get('name', '')[:24]}] {' | '.join(extra)}")
        for c in by_parent.get(s["spanId"], []):
            walk(c, depth + 1)

    for root in by_parent.get("", []):
        walk(root, 0)
