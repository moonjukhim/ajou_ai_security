"""2회차 AWS 방어 데모 공통 모듈

- AWS_REGION        : 기본 us-west-2 (Bedrock Guardrails·Verified Permissions·DNS Firewall)
- GUARDRAIL_TIER    : STANDARD(기본, 한국어 등 다국어 지원) | CLASSIC
- GUARDRAIL_PROFILE : Standard 티어의 교차 리전 프로필 (기본: 리전에 맞춰 us./eu./apac.guardrail.v1:0)

모든 리소스 이름은 'ajou-ai-sec-' 로 시작하며, 각 노트북 마지막 셀에서 삭제합니다.
"""
import os, time, unicodedata

import boto3
from botocore.exceptions import ClientError

REGION = os.getenv("AWS_REGION", "us-west-2")
PREFIX = "ajou-ai-sec"


def client(name, region=None):
    return boto3.client(name, region_name=region or REGION)


def whoami():
    ident = client("sts").get_caller_identity()
    print(f"[AWS] 계정 {ident['Account']} · 리전 {REGION} · {ident['Arn'].split('/')[-1]}")
    return ident["Account"]


def show_table(rows, headers):
    """간단한 표 출력 (pandas 없이, 한글 폭 보정)"""
    def w(s):
        return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in str(s))
    widths = [max(w(h), *(w(r[i]) for r in rows)) for i, h in enumerate(headers)]
    line = lambda cells: " | ".join(str(c) + " " * (widths[i] - w(c)) for i, c in enumerate(cells))
    print(line(headers))
    print("-+-".join("-" * x for x in widths))
    for r in rows:
        print(line(r))


# ------------------------------------------------------------------ Bedrock Guardrails
def _profile():
    geo = {"us": "us", "eu": "eu", "ap": "apac"}.get(REGION.split("-")[0], "us")
    return os.getenv("GUARDRAIL_PROFILE", f"{geo}.guardrail.v1:0")


def _wait(br, gid, version=None, timeout=120):
    kw = {"guardrailIdentifier": gid}
    if version:
        kw["guardrailVersion"] = version
    t0 = time.time()
    while time.time() - t0 < timeout:
        st = br.get_guardrail(**kw)["status"]
        if st == "READY":
            return
        if st == "FAILED":
            raise RuntimeError(f"가드레일 생성 실패: {gid}")
        time.sleep(3)
    raise TimeoutError("가드레일이 READY 상태가 되지 않았습니다")


def delete_guardrails(name_prefix=PREFIX):
    """이름이 name_prefix 로 시작하는 가드레일을 모두 삭제 (재실행·정리용)"""
    br = client("bedrock")
    for page in br.get_paginator("list_guardrails").paginate():
        for g in page["guardrails"]:
            if g["name"].startswith(name_prefix):
                br.delete_guardrail(guardrailIdentifier=g["id"])
                print(f"[삭제] 가드레일 {g['name']} ({g['id']})")


def create_guardrail(name, description="", *, prompt_attack="HIGH", harmful="MEDIUM",
                     topics=(), topic_input="BLOCK", topic_output="BLOCK",
                     words=(), regexes=(), pii=(), tier=None,
                     blocked_input="요청이 보안 정책에 의해 차단되었습니다.",
                     blocked_output="응답이 보안 정책에 의해 차단되었습니다."):
    """가드레일을 만들고 버전을 발행한 뒤 (id, version, tier) 반환

    topics : [(name(영문), definition, [examples])]   → 거부 주제
    topic_input / topic_output : "BLOCK" | "NONE"     → NONE이면 '감지만' 하고 통과(탐지 모드)
    words  : ["금칙어", ...]                           → 단어 필터
    regexes: [(name, pattern, "BLOCK"|"ANONYMIZE")]    → 사용자 정의 민감정보
    pii    : [("PHONE"|"EMAIL"|..., "BLOCK"|"ANONYMIZE")]
    """
    br = client("bedrock")
    tier = tier or os.getenv("GUARDRAIL_TIER", "STANDARD")
    delete_guardrails(name)  # 같은 이름이 있으면 정리 후 재생성

    filters = []
    if harmful:
        filters += [{"type": t, "inputStrength": harmful, "outputStrength": harmful}
                    for t in ("SEXUAL", "VIOLENCE", "HATE", "INSULTS", "MISCONDUCT")]
    if prompt_attack:
        filters.append({"type": "PROMPT_ATTACK", "inputStrength": prompt_attack, "outputStrength": "NONE"})

    def build(tier):
        kw = {"name": name, "description": description[:200],
              "blockedInputMessaging": blocked_input, "blockedOutputsMessaging": blocked_output}
        if filters:
            kw["contentPolicyConfig"] = {"filtersConfig": filters}
        if topics:
            kw["topicPolicyConfig"] = {"topicsConfig": [
                {"name": n, "definition": d, "examples": list(ex)[:5], "type": "DENY",
                 "inputAction": topic_input, "outputAction": topic_output} for n, d, ex in topics]}
        if words:
            kw["wordPolicyConfig"] = {"wordsConfig": [{"text": w} for w in words]}
        if regexes or pii:
            sip = {}
            if pii:
                sip["piiEntitiesConfig"] = [{"type": t, "action": a} for t, a in pii]
            if regexes:
                sip["regexesConfig"] = [{"name": n, "pattern": p, "action": a} for n, p, a in regexes]
            kw["sensitiveInformationPolicyConfig"] = sip
        if tier == "STANDARD":
            kw["crossRegionConfig"] = {"guardrailProfileIdentifier": _profile()}
            for key in ("contentPolicyConfig", "topicPolicyConfig"):
                if key in kw:
                    kw[key]["tierConfig"] = {"tierName": "STANDARD"}
        return kw

    try:
        gid = br.create_guardrail(**build(tier))["guardrailId"]
    except ClientError as e:
        if tier != "STANDARD":
            raise
        print(f"[주의] Standard 티어 생성 실패 → Classic 으로 재시도 ({e.response['Error']['Message'][:120]})")
        print("       Classic 티어는 영어·프랑스어·스페인어 중심이라 한국어 탐지율이 낮을 수 있습니다.")
        tier = "CLASSIC"
        gid = br.create_guardrail(**build(tier))["guardrailId"]
    _wait(br, gid)
    ver = br.create_guardrail_version(guardrailIdentifier=gid, description="demo")["version"]
    _wait(br, gid, ver)
    print(f"[생성] 가드레일 {name} · id={gid} · version={ver} · tier={tier}")
    return gid, ver, tier


def _reasons(assessments):
    """ApplyGuardrail 평가 결과에서 '개입한' 정책만 짧은 문자열로"""
    out = []
    for a in assessments:
        for t in a.get("topicPolicy", {}).get("topics", []):
            if t.get("action") == "BLOCKED":
                out.append(f"주제:{t['name']}")
            elif t.get("detected"):
                out.append(f"감지만:{t['name']}")
        for f in a.get("contentPolicy", {}).get("filters", []):
            if f.get("action") == "BLOCKED":
                out.append(f"{f['type']}({f.get('confidence', '')})")
        for k in ("customWords", "managedWordLists"):
            for w in a.get("wordPolicy", {}).get(k, []):
                if w.get("action") == "BLOCKED":
                    out.append(f"단어:{w['match']}")
        sip = a.get("sensitiveInformationPolicy", {})
        for p in sip.get("piiEntities", []):
            if p.get("action") in ("BLOCKED", "ANONYMIZED"):
                out.append(f"PII:{p['type']}→{p['action']}")
        for r in sip.get("regexes", []):
            if r.get("action") in ("BLOCKED", "ANONYMIZED"):
                out.append(f"정규식:{r['name']}→{r['action']}")
    return out


def apply_guardrail(gid, ver, text, source="INPUT"):
    """텍스트 한 덩어리를 가드레일로 검사 → (개입 여부, 사유 목록, 가드레일이 돌려준 텍스트)"""
    rt = client("bedrock-runtime")
    resp = rt.apply_guardrail(guardrailIdentifier=gid, guardrailVersion=ver, source=source,
                              content=[{"text": {"text": text}}])
    hit = resp["action"] == "GUARDRAIL_INTERVENED"
    shown = "".join(o.get("text", "") for o in resp.get("outputs", [])) if hit else text
    return hit, _reasons(resp.get("assessments", [])), shown
