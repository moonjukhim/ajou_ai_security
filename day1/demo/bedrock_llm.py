"""1회차 공인교재 데모 · Amazon Bedrock LLM 연결 모듈

모든 LLM 호출은 Amazon Bedrock Converse API로 보냅니다.

    import bedrock_llm as L
    L.setup(model="us.amazon.nova-lite-v1:0", region="us-west-2", profile=None)
    L.chat(system, user)                       # 텍스트 한 번 생성
    L.tool_turn(system, messages, tools)       # 에이전트 한 스텝 (도구 호출 포함)
    with L.use_model("us.anthropic.claude-haiku-4-5-20251001-v1:0"): ...   # 잠시 다른 모델로

필요 권한: bedrock:InvokeModel (사용할 추론 프로필과 기반 모델), sts:GetCallerIdentity
환경 변수로도 지정 가능: AWS_REGION, AWS_PROFILE, BEDROCK_MODEL_ID
"""
import os, re, time
from contextlib import contextmanager

DEFAULT_MODEL = "us.amazon.nova-lite-v1:0"
DEFAULT_REGION = "us-west-2"
_state = {"client": None, "model": None, "region": None}


def setup(model=None, region=None, profile=None, quiet=False):
    """Bedrock 클라이언트를 만들고 자격 증명과 모델 접근을 확인한 뒤 모델 ID를 반환"""
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

    model = model or os.getenv("BEDROCK_MODEL_ID", DEFAULT_MODEL)
    region = region or os.getenv("AWS_REGION", DEFAULT_REGION)
    profile = profile or os.getenv("AWS_PROFILE") or None
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        ident = session.client("sts").get_caller_identity()
    except (NoCredentialsError, ProfileNotFound, ClientError) as e:
        raise RuntimeError(
            "AWS 자격 증명을 찾지 못했습니다.\n"
            "  - 터미널에서 `aws configure` 또는 `aws sso login --profile <이름>` 을 실행하거나\n"
            "  - 노트북 첫 셀의 AWS_PROFILE 에 프로필 이름을 넣으세요.\n"
            f"  원인: {e}") from None
    client = session.client("bedrock-runtime")
    try:   # 모델 접근 확인 (아주 짧은 호출)
        client.converse(modelId=model, messages=[{"role": "user", "content": [{"text": "ping"}]}],
                        inferenceConfig={"maxTokens": 5, "temperature": 0})
    except ClientError as e:
        code = e.response["Error"]["Code"]
        hint = {"AccessDeniedException": "IAM 권한(bedrock:InvokeModel) 또는 Bedrock 콘솔의 모델 액세스를 확인하세요.",
                "ValidationException": "모델 ID나 리전이 맞는지 확인하세요 (us. 접두어 추론 프로필은 미국 리전용).",
                "ResourceNotFoundException": "이 리전에서 쓸 수 없거나 지원 종료된 모델입니다. 다른 모델 ID를 지정하세요."}.get(code, "")
        raise RuntimeError(f"Bedrock 모델 호출 실패 ({code}): {model} @ {region}\n  {hint}\n  원인: {e}") from None
    _state.update(client=client, model=model, region=region)
    if not quiet:
        print(f"[Bedrock] 계정 ********{ident['Account'][-4:]} · 리전 {region} · 모델 {model}")
    return model


def model():
    if _state["client"] is None:
        setup()
    return _state["model"]


@contextmanager
def use_model(model_id):
    """with 블록 안에서만 다른 모델을 사용 (같은 리전·자격 증명)"""
    model()
    prev = _state["model"]
    _state["model"] = model_id
    try:
        yield model_id
    finally:
        _state["model"] = prev


def clean(text):
    """일부 모델(Nova 등)이 붙이는 <thinking>…</thinking> 구간과 <response>/<answer> 태그를 지운 답변"""
    text = re.sub(r"<thinking>.*?(</thinking>|$)", "", text or "", flags=re.S)
    return re.sub(r"</?(response|answer)>", "", text).strip()


def _converse(**kw):
    """재시도 포함 Converse 호출. 소형 모델의 잘못된 도구 호출(ModelErrorException)과 Throttling을 재시도"""
    from botocore.exceptions import ClientError
    model()
    for attempt in range(4):
        try:
            return _state["client"].converse(modelId=_state["model"], **kw)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ("ModelErrorException", "ThrottlingException") or attempt == 3:
                if code == "ModelErrorException":
                    return None
                raise
            kw.setdefault("inferenceConfig", {})["temperature"] = 0.3
            time.sleep(1 + attempt)


def chat(system, user, max_tokens=500):
    """system/user 프롬프트로 한 번 호출해 텍스트를 반환"""
    resp = _converse(system=[{"text": system}], messages=[{"role": "user", "content": [{"text": user}]}],
                     inferenceConfig={"maxTokens": max_tokens, "temperature": 0})
    if resp is None:
        return "(모델 오류)"
    return "".join(c.get("text", "") for c in resp["output"]["message"]["content"]).strip()


def tool_turn(system, messages, tools, max_tokens=700):
    """에이전트 한 스텝. 반환 {"text": str, "calls": [{"id", "name", "args"}]}

    messages (공통 형식):
      {"role": "user", "content": str}
      {"role": "assistant", "text": str, "calls": [{"id", "name", "args"}]}
      {"role": "tool", "id": str, "name": str, "content": str}
    tools: [{"name", "description", "params": {param: description}}]
    """
    schema = lambda t: {"type": "object",
                        "properties": {k: {"type": "string", "description": v} for k, v in t["params"].items()},
                        "required": list(t["params"])}
    tool_config = {"tools": [{"toolSpec": {"name": t["name"], "description": t["description"],
                                           "inputSchema": {"json": schema(t)}}} for t in tools]}
    bmsgs = []
    for x in messages:
        if x["role"] == "user":
            bmsgs.append({"role": "user", "content": [{"text": x["content"]}]})
        elif x["role"] == "assistant":
            content = ([{"text": x["text"]}] if x.get("text") else []) + \
                      [{"toolUse": {"toolUseId": c["id"], "name": c["name"], "input": c["args"]}} for c in x.get("calls", [])]
            bmsgs.append({"role": "assistant", "content": content})
        else:
            block = {"toolResult": {"toolUseId": x["id"], "content": [{"text": x["content"]}]}}
            if bmsgs and bmsgs[-1]["role"] == "user" and "toolResult" in bmsgs[-1]["content"][0]:
                bmsgs[-1]["content"].append(block)
            else:
                bmsgs.append({"role": "user", "content": [block]})
    resp = _converse(system=[{"text": system}], messages=bmsgs, toolConfig=tool_config,
                     inferenceConfig={"maxTokens": max_tokens, "temperature": 0})
    if resp is None:
        return {"text": "(모델이 올바른 도구 호출을 만들지 못함)", "calls": []}
    content = resp["output"]["message"]["content"]
    return {"text": "".join(c.get("text", "") for c in content).strip(),
            "calls": [{"id": c["toolUse"]["toolUseId"], "name": c["toolUse"]["name"], "args": c["toolUse"]["input"]}
                      for c in content if "toolUse" in c]}
