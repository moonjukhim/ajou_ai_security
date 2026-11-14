"""3회차 AWS 데모 공용 인프라 만들기·지우기 (00_setup / 99_cleanup 노트북이 단계별로 호출).

만드는 것 (이름은 모두 ajou-aisec3x… 로 시작, LAB_SUFFIX로 구분)
- Amazon Cognito 사용자 풀: 사내 디렉터리 (사용자 7명, 그룹 6개)
- AWS Secrets Manager: 직원 휴대폰 인증 앱의 TOTP 시드
- Amazon DynamoDB: 확인 기록 · 변경 기록 · 티켓 · 감사 기록 · 승인 요청 (단일 테이블)
- Amazon CloudWatch Logs: u-3001 로그인 기록 800건
- Amazon S3 + S3 Vectors + Bedrock Knowledge Base: 사내 IT KB 6건
- Amazon Bedrock AgentCore Runtime: 헬프데스크 에이전트 (agent_runtime/, S3의 zip으로 직접 코드 배포)
- Amazon EventBridge 규칙 + AWS Lambda: 보안 경보 → 에이전트 자동 호출 (범위 4)
- (계정 설정) X-Ray Transaction Search: 스팬을 CloudWatch Logs(aws/spans)로
"""
from __future__ import annotations

import io
import json
import os
import random
import secrets
import string
import time
import zipfile
from datetime import datetime, timedelta, timezone

import boto3

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "lab_config.json")


def _read(path: str) -> dict:
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _owner_account(c: dict) -> str | None:
    if c.get("account"):
        return c["account"]
    for k in ("user_pool_arn", "runtime_arn", "totp_secret_arn", "runtime_role_arn"):
        parts = (c.get(k) or "").split(":")
        if len(parts) > 4 and parts[4]:
            return parts[4]
    return None


def _restore_moved_config(env_region: str | None) -> None:
    """예전 버전이 리전 차이 때문에 옮겨 둔 같은 계정의 설정 파일(lab_config.json.other-*)을 되살린다."""
    import glob
    if os.path.exists(CONFIG_PATH):
        return
    cands = [(p, _read(p)) for p in glob.glob(CONFIG_PATH + ".other-*")]
    cands = [(p, c) for p, c in cands if c.get("runtime_arn") or c.get("user_pool_id")]
    if not cands:
        return
    acct = boto3.client("sts").get_caller_identity()["Account"]
    cands = [(p, c) for p, c in cands if _owner_account(c) in (None, acct)]
    want = env_region or boto3.session.Session().region_name
    cands.sort(key=lambda pc: (pc[1].get("region") == want, os.path.getmtime(pc[0])), reverse=True)
    if cands:
        os.rename(cands[0][0], CONFIG_PATH)
        print(f"↺ 옮겨져 있던 설정 파일 {os.path.basename(cands[0][0])}을 lab_config.json으로 되살렸습니다 "
              f"(리전 {cands[0][1].get('region')}).")


# 리전 결정: 환경 변수(AWS_REGION·AWS_DEFAULT_REGION) → 00_setup이 저장한 설정 파일의 리전 → boto3 기본 리전 → us-west-2
_ENV_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
_restore_moved_config(_ENV_REGION)
_FILE = _read(CONFIG_PATH) if os.path.exists(CONFIG_PATH) else {}
REGION = _ENV_REGION or _FILE.get("region") or boto3.session.Session().region_name or "us-west-2"
SUFFIX = (os.environ.get("LAB_SUFFIX") or _FILE.get("suffix") or "demo").lower()
P = f"ajou-aisec3x-{SUFFIX}"          # 하이픈 이름
PU = P.replace("-", "_")               # 밑줄 이름 (AgentCore 등)
PR = f"{P}-{REGION}"                   # IAM 역할 이름: IAM은 계정 전체에서 하나라 리전을 넣어 다른 리전 실습과 충돌 방지

KB_DOCS = {
    "KB-101": ("VPN 오류 E-809", "VPN 접속 오류 E-809가 나면 GlobalProtect 클라이언트를 6.2 이상으로 업데이트한다. "
               "업데이트 후에도 실패하면 헬프데스크(내선 4410)에 티켓을 연다."),
    "KB-102": ("계정 잠금", "비밀번호를 5회 틀리면 계정이 30분 잠긴다. 헬프데스크는 OTP로 본인 확인을 마친 뒤에만 잠금을 해제할 수 있다."),
    "KB-103": ("비밀번호 초기화", "비밀번호 초기화는 OTP 본인 확인 후에만 한다. 임시 비밀번호는 등록된 휴대폰으로만 SMS 발송하며 채팅이나 메일로 알려 주지 않는다."),
    "KB-104": ("권한 그룹 추가", "Domain Admins, Finance-Approvers 같은 권한 그룹 추가는 보안팀 승인과 변경 관리 티켓이 필요하다. 헬프데스크는 처리할 수 없다."),
    "KB-105": ("MFA 기기 분실", "MFA 기기를 잃어버린 경우 신분증을 지참하고 IT 데스크(본관 3층)에서 대면으로 처리한다. 원격으로 MFA를 해제하지 않는다."),
    "KB-106": ("소프트웨어 설치", "승인 목록(Slack, Zoom, VS Code)에 있는 소프트웨어만 셀프서비스 포털에서 설치할 수 있다. 그 밖의 소프트웨어는 보안 검토 티켓을 연다."),
}
USERS = {   # 기준 상태 (reset_directory가 매 시나리오 전에 이 상태로 되돌림)
    "u-1024": {"name": "김민수", "dept": "영업팀", "locked": True, "groups": ["Sales"]},
    "u-2048": {"name": "이서연", "dept": "개발팀", "locked": False, "groups": ["Dev"]},
    "u-3001": {"name": "박지훈", "dept": "재무팀", "locked": False, "groups": ["Finance", "Finance-Approvers"]},
    "u-3002": {"name": "정다은", "dept": "재무팀", "locked": False, "groups": ["Finance"]},
    "u-3003": {"name": "한승우", "dept": "재무팀", "locked": False, "groups": ["Finance"]},
    "u-3004": {"name": "오지민", "dept": "재무팀", "locked": False, "groups": ["Finance"]},
    "u-4096": {"name": "최유진", "dept": "인사팀", "locked": True, "groups": ["HR"]},
}
GROUPS = ["Sales", "Dev", "Finance", "Finance-Approvers", "HR", "Domain-Admins"]   # Cognito 그룹 이름에는 공백 불가
TOTP_USERS = ["u-1024", "u-2048", "u-4096"]   # 인증 앱을 등록한 직원 (u-3001은 본인 휴대폰에만 있음)


_ACCOUNT: str | None = None
_CHECKED = False


def account_id() -> str:
    global _ACCOUNT
    if _ACCOUNT is None:
        _ACCOUNT = boto3.client("sts").get_caller_identity()["Account"]
    return _ACCOUNT


def _config_owner(c: dict) -> tuple[str | None, str | None]:
    """설정 파일이 어느 계정·리전에서 만들어졌는지 (account 키가 없는 예전 파일은 ARN에서 읽음)."""
    if c.get("account"):
        return c["account"], c.get("region")
    for k in ("user_pool_arn", "runtime_arn", "totp_secret_arn", "runtime_role_arn"):
        v = c.get(k) or ""
        parts = v.split(":")
        if len(parts) > 4 and parts[4]:
            return parts[4], parts[3] or c.get("region")
    return None, c.get("region")


def load() -> dict:
    """lab_config.json을 읽는다. 다른 계정·리전·LAB_SUFFIX에서 만든 파일이면 따로 보관하고 빈 설정으로 시작."""
    global _CHECKED
    if not os.path.exists(CONFIG_PATH):
        return {}
    c = json.load(open(CONFIG_PATH, encoding="utf-8"))
    if not _CHECKED:
        _CHECKED = True
        acct, reg = _config_owner(c)
        if acct and acct != account_id():
            # 다른 AWS 계정에서 만든 파일(폴더째 복사해 온 경우) → 옆으로 옮기고 새로 시작
            keep = f"{CONFIG_PATH}.other-{acct[-4:]}-{reg}-{c.get('suffix')}-{int(time.time())}"
            os.rename(CONFIG_PATH, keep)
            print(f"⚠️ lab_config.json이 다른 계정(…{acct[-4:]})의 것이라 {os.path.basename(keep)}로 옮기고 새로 시작합니다.")
            return {}
        if (reg and reg != REGION) or c.get("suffix", SUFFIX) != SUFFIX:
            raise RuntimeError(
                f"lab_config.json은 리전 {reg} · LAB_SUFFIX {c.get('suffix')}로 만들어졌는데, 지금 커널은 리전 {REGION} · "
                f"LAB_SUFFIX {SUFFIX}입니다.\n→ 환경 변수 AWS_REGION/AWS_DEFAULT_REGION/LAB_SUFFIX를 지우거나 "
                f"{reg} · {c.get('suffix')}로 맞춘 뒤 커널을 재시작하세요. (설정하지 않으면 설정 파일의 리전을 자동으로 씁니다)")
    return c


def save(**kw) -> dict:
    c = load(); c.update(kw); c.setdefault("region", REGION); c.setdefault("suffix", SUFFIX)
    c.setdefault("account", account_id())
    json.dump(c, open(CONFIG_PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    return c


def _wait(fn, ok, what, timeout=600, every=5):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = fn()
        if ok(v):
            return v
        time.sleep(every)
    raise TimeoutError(f"{what} 대기 시간 초과")


def _create_bucket(s3, name: str) -> None:
    """S3 버킷 생성. us-east-1은 LocationConstraint를 넣으면 오류(InvalidLocationConstraint)라서 빼야 함."""
    kw = {} if REGION == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": REGION}}
    for attempt in range(10):
        try:
            s3.create_bucket(Bucket=name, **kw)
            return
        except (s3.exceptions.BucketAlreadyOwnedByYou, s3.exceptions.BucketAlreadyExists):
            return
        except s3.exceptions.ClientError as e:
            # OperationAborted: 같은 이름의 버킷을 방금 다른 곳에서 만들거나 지우는 중 → 잠시 뒤 재시도
            if e.response["Error"]["Code"] != "OperationAborted" or attempt == 9:
                raise
            print(f"  S3 버킷 {name}: 다른 작업 진행 중(OperationAborted) — 20초 뒤 재시도 ({attempt + 1}/10)")
            time.sleep(20)


def _role(name: str, service: str, policy: dict, extra_trust: dict | None = None) -> str:
    iam = boto3.client("iam")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole",
                                                     **(extra_trust or {})}]}
    try:
        arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    except iam.exceptions.EntityAlreadyExistsException:
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(trust))
    iam.put_role_policy(RoleName=name, PolicyName="lab", PolicyDocument=json.dumps(policy))
    return arn


# ---------------------------------------------------------------------------
# 1. X-Ray Transaction Search (계정 설정)
# ---------------------------------------------------------------------------
def ensure_transaction_search() -> dict:
    xray, logs, acct = boto3.client("xray", region_name=REGION), boto3.client("logs", region_name=REGION), account_id()
    before = xray.get_trace_segment_destination()
    if before["Destination"] == "CloudWatchLogs":
        save(transaction_search_changed=False)
        return {"before": before, "changed": False}
    logs.put_resource_policy(policyName="ajou-aisec3x-TransactionSearchXRayAccess", policyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Sid": "TransactionSearchXRayAccess", "Effect": "Allow", "Principal": {"Service": "xray.amazonaws.com"},
            "Action": "logs:PutLogEvents",
            "Resource": [f"arn:aws:logs:{REGION}:{acct}:log-group:aws/spans:*",
                         f"arn:aws:logs:{REGION}:{acct}:log-group:/aws/application-signals/data:*"],
            "Condition": {"ArnLike": {"aws:SourceArn": f"arn:aws:xray:{REGION}:{acct}:*"},
                          "StringEquals": {"aws:SourceAccount": acct}}}]}))
    xray.update_trace_segment_destination(Destination="CloudWatchLogs")
    save(transaction_search_changed=True, transaction_search_before=before["Destination"])
    return {"before": before, "changed": True, "after": xray.get_trace_segment_destination()}


# ---------------------------------------------------------------------------
# 2. 디렉터리 · 시드 · 테이블 · 로그인 기록
# ---------------------------------------------------------------------------
def create_table() -> str:
    ddb, name = boto3.client("dynamodb", region_name=REGION), f"{P}-helpdesk"
    try:
        ddb.create_table(TableName=name, BillingMode="PAY_PER_REQUEST",
                         AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
                         KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}])
    except ddb.exceptions.ResourceInUseException:
        pass
    ddb.get_waiter("table_exists").wait(TableName=name)
    try:
        ddb.update_time_to_live(TableName=name, TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"})
    except ddb.exceptions.ClientError:
        pass
    save(table=name)
    return name


def create_totp_secret() -> str:
    sm, name = boto3.client("secretsmanager", region_name=REGION), f"{P}/totp-seeds"
    seeds = {u: "".join(random.SystemRandom().choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(32)) for u in TOTP_USERS}
    try:
        arn = sm.create_secret(Name=name, SecretString=json.dumps(seeds), Description="3회차 데모: 직원 인증 앱 TOTP 시드 (가상)")["ARN"]
    except sm.exceptions.ResourceExistsException:
        arn = sm.describe_secret(SecretId=name)["ARN"]
    save(totp_secret=name, totp_secret_arn=arn)
    return name


def create_directory() -> str:
    idp = boto3.client("cognito-idp", region_name=REGION)
    c = load()
    if c.get("user_pool_id"):
        try:
            arn = idp.describe_user_pool(UserPoolId=c["user_pool_id"])["UserPool"]["Arn"]
            save(user_pool_arn=arn)
            reset_directory()
            return c["user_pool_id"]
        except idp.exceptions.ResourceNotFoundException:
            pass
    # 설정 파일에 없더라도 이 리전에 같은 이름의 디렉터리가 있으면 재사용 (중복 생성 방지)
    same = [p for p in idp.list_user_pools(MaxResults=60)["UserPools"] if p["Name"] == f"{P}-directory"]
    if same:
        pid = same[0]["Id"]
        save(user_pool_id=pid, user_pool_arn=idp.describe_user_pool(UserPoolId=pid)["UserPool"]["Arn"])
        reset_directory()
        return pid
    pool = idp.create_user_pool(
        PoolName=f"{P}-directory", MfaConfiguration="OFF", DeletionProtection="INACTIVE",
        Schema=[{"Name": "dept", "AttributeDataType": "String", "Mutable": True},
                {"Name": "mfa", "AttributeDataType": "String", "Mutable": True}],
        Policies={"PasswordPolicy": {"MinimumLength": 12, "RequireUppercase": True, "RequireLowercase": True,
                                     "RequireNumbers": True, "RequireSymbols": True}},
        AdminCreateUserConfig={"AllowAdminCreateUserOnly": True})["UserPool"]
    pid = pool["Id"]
    for g in GROUPS:
        idp.create_group(UserPoolId=pid, GroupName=g)
    for uid, u in USERS.items():
        idp.admin_create_user(UserPoolId=pid, Username=uid, MessageAction="SUPPRESS",
                              UserAttributes=[{"Name": "name", "Value": u["name"]}, {"Name": "custom:dept", "Value": u["dept"]},
                                              {"Name": "custom:mfa", "Value": "on"}])
    save(user_pool_id=pid, user_pool_arn=pool["Arn"])
    reset_directory()
    return pid


def _strong_password() -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(14)) + "!aA1"


def reset_directory(users: list[str] | None = None) -> None:
    """디렉터리를 기준 상태로 되돌린다 (잠금 상태 · 그룹 · MFA 속성 · 비밀번호 상태)."""
    idp, pid = boto3.client("cognito-idp", region_name=REGION), load()["user_pool_id"]
    for uid in users or USERS:
        u = USERS[uid]
        (idp.admin_disable_user if u["locked"] else idp.admin_enable_user)(UserPoolId=pid, Username=uid)
        idp.admin_update_user_attributes(UserPoolId=pid, Username=uid, UserAttributes=[{"Name": "custom:mfa", "Value": "on"}])
        idp.admin_set_user_password(UserPoolId=pid, Username=uid, Password=_strong_password(), Permanent=True)
        have = {g["GroupName"] for g in idp.admin_list_groups_for_user(UserPoolId=pid, Username=uid)["Groups"]}
        for g in have - set(u["groups"]):
            idp.admin_remove_user_from_group(UserPoolId=pid, Username=uid, GroupName=g)
        for g in set(u["groups"]) - have:
            idp.admin_add_user_to_group(UserPoolId=pid, Username=uid, GroupName=g)


def create_login_events() -> str:
    logs, name = boto3.client("logs", region_name=REGION), f"/{P}/login-events"
    try:
        logs.create_log_group(logGroupName=name)
        logs.put_retention_policy(logGroupName=name, retentionInDays=14)
    except logs.exceptions.ResourceAlreadyExistsException:
        save(login_log_group=name)
        return name
    logs.create_log_stream(logGroupName=name, logStreamName="u-3001")
    rng = random.Random(42)
    start = datetime.now(timezone.utc) - timedelta(days=10)
    events = []
    for i in range(800):   # 20건씩 40페이지
        t = start + timedelta(minutes=18 * i)
        ip = f"10.20.{rng.randint(0, 3)}.{rng.randint(2, 250)}"
        events.append({"timestamp": int(t.timestamp() * 1000),
                       "message": json.dumps({"t": t.isoformat(timespec="minutes"), "user": "u-3001", "ip": ip,
                                              "result": "fail" if rng.random() < 0.12 else "success"})})
    for i in range(0, len(events), 70):   # PutLogEvents 한 번은 24시간 범위 안이어야 함 (18분 간격 × 70 ≈ 21시간)
        logs.put_log_events(logGroupName=name, logStreamName="u-3001", logEvents=events[i:i + 70])
    save(login_log_group=name)
    return name


# ---------------------------------------------------------------------------
# 3. Bedrock Knowledge Base (S3 Vectors)
# ---------------------------------------------------------------------------
def create_knowledge_base() -> str:
    acct = account_id()
    s3, s3v = boto3.client("s3", region_name=REGION), boto3.client("s3vectors", region_name=REGION)
    ba, iam = boto3.client("bedrock-agent", region_name=REGION), boto3.client("iam")
    bucket, vbucket, index = f"{P}-kb-{acct}-{REGION}", f"{P}-vectors", "helpdesk-kb"   # 리전을 넣어 다른 리전의 같은 이름과 충돌 방지
    c = load()
    if c.get("kb_id"):          # 저장된 KB가 이 계정에 실제로 있으면 재사용, 없으면 새로 만듦
        try:
            if ba.get_knowledge_base(knowledgeBaseId=c["kb_id"])["knowledgeBase"]["status"] == "ACTIVE":
                return c["kb_id"]
        except ba.exceptions.ResourceNotFoundException:
            pass
        print(f"⚠️ 저장된 Knowledge Base {c['kb_id']}가 이 계정·리전에 없어 새로 만듭니다.")
        save(kb_id=None, kb_data_source=None, kb_docs_indexed=None)
    _create_bucket(s3, bucket)
    s3.get_waiter("bucket_exists").wait(Bucket=bucket)
    loc = s3.get_bucket_location(Bucket=bucket)["LocationConstraint"] or "us-east-1"
    if loc != REGION:
        raise RuntimeError(f"KB 문서 버킷 {bucket}이 {loc} 리전에 있습니다. KB({REGION})와 같은 리전이어야 합니다.")
    for k, (title, body) in KB_DOCS.items():
        s3.put_object(Bucket=bucket, Key=f"kb/{k}.md", Body=f"# {k} {title}\n\n{body}\n".encode("utf-8"), ContentType="text/markdown")
    try:
        s3v.create_vector_bucket(vectorBucketName=vbucket)
    except s3v.exceptions.ConflictException:
        pass
    try:
        s3v.create_index(vectorBucketName=vbucket, indexName=index, dataType="float32", dimension=1024, distanceMetric="cosine",
                         metadataConfiguration={"nonFilterableMetadataKeys": ["AMAZON_BEDROCK_TEXT"]})
    except s3v.exceptions.ConflictException:
        pass
    index_arn = s3v.get_index(vectorBucketName=vbucket, indexName=index)["index"]["indexArn"]
    vbucket_arn = f"arn:aws:s3vectors:{REGION}:{acct}:bucket/{vbucket}"
    emb = f"arn:aws:bedrock:{REGION}::foundation-model/amazon.titan-embed-text-v2:0"
    role_arn = _role(f"{PR}-kb-role", "bedrock.amazonaws.com", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": emb},
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
        {"Effect": "Allow", "Action": ["s3vectors:PutVectors", "s3vectors:GetVectors", "s3vectors:DeleteVectors",
                                       "s3vectors:QueryVectors", "s3vectors:GetIndex"], "Resource": [vbucket_arn, index_arn]}]},
        {"Condition": {"StringEquals": {"aws:SourceAccount": acct}}})
    # 이전 실행이 중간에 실패해 같은 이름의 KB가 남아 있으면 재사용
    existing = [k for k in ba.list_knowledge_bases(maxResults=100)["knowledgeBaseSummaries"] if k["name"] == f"{P}-kb"]
    if existing:
        kb_id = existing[0]["knowledgeBaseId"]
        print(f"이전 실행에서 만든 Knowledge Base {kb_id}를 재사용합니다.")
        cur = ba.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]
        if cur["roleArn"] != role_arn:          # 예전(리전 없는) 역할을 쓰고 있으면 이 리전 전용 역할로 교체
            print(f"  KB 역할을 {role_arn.rsplit('/', 1)[-1]}로 바꿉니다.")
            for attempt in range(12):
                try:
                    ba.update_knowledge_base(knowledgeBaseId=kb_id, name=cur["name"], roleArn=role_arn,
                                             knowledgeBaseConfiguration=cur["knowledgeBaseConfiguration"],
                                             storageConfiguration=cur["storageConfiguration"])
                    break
                except ba.exceptions.ValidationException:
                    if attempt == 11:
                        raise
                    time.sleep(10)
    else:
        for attempt in range(12):   # IAM 전파 대기
            try:
                kb = ba.create_knowledge_base(
                    name=f"{P}-kb", roleArn=role_arn,
                    knowledgeBaseConfiguration={"type": "VECTOR", "vectorKnowledgeBaseConfiguration": {
                        "embeddingModelArn": emb,
                        "embeddingModelConfiguration": {"bedrockEmbeddingModelConfiguration": {"dimensions": 1024}}}},
                    storageConfiguration={"type": "S3_VECTORS", "s3VectorsConfiguration": {"indexArn": index_arn}})["knowledgeBase"]
                break
            except ba.exceptions.ValidationException:
                if attempt == 11:
                    raise
                time.sleep(10)
        kb_id = kb["knowledgeBaseId"]
    save(kb_id_pending=kb_id)
    _wait(lambda: ba.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"], lambda s: s == "ACTIVE", "KB")
    ds_cfg = {"type": "S3", "s3Configuration": {"bucketArn": f"arn:aws:s3:::{bucket}", "inclusionPrefixes": ["kb/"]}}
    dss = [d for d in ba.list_data_sources(knowledgeBaseId=kb_id)["dataSourceSummaries"] if d["name"] == "helpdesk-docs"]
    if dss:
        ds_id = dss[0]["dataSourceId"]
        cur = ba.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]
        if cur["dataSourceConfiguration"].get("s3Configuration", {}).get("bucketArn") != ds_cfg["s3Configuration"]["bucketArn"]:
            print(f"  데이터 원본을 새 문서 버킷 {bucket}로 바꿉니다.")
            ba.update_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id, name="helpdesk-docs", dataSourceConfiguration=ds_cfg,
                                  vectorIngestionConfiguration={"chunkingConfiguration": {"chunkingStrategy": "NONE"}})
    else:
        ds_id = ba.create_data_source(knowledgeBaseId=kb_id, name="helpdesk-docs", dataSourceConfiguration=ds_cfg,
                                      vectorIngestionConfiguration={"chunkingConfiguration": {"chunkingStrategy": "NONE"}})["dataSource"]["dataSourceId"]
    # 방금 만든 S3 버킷은 DNS가 퍼지기 전까지 307(임시 리디렉션)을 돌려줄 수 있음 → 기다렸다가 수집을 다시 시도
    for attempt in range(8):
        for t in range(18):   # 방금 만들거나 바꾼 KB 역할을 Bedrock이 아직 맡지 못하면(IAM 전파 전) 기다렸다가 다시 시작
            try:
                job = ba.start_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id)["ingestionJob"]
                break
            except ba.exceptions.ValidationException as e:
                if "assume" not in str(e) or t == 17:
                    raise
                print(f"  KB 역할 전파 대기 중(역할을 아직 맡지 못함) — 10초 뒤 재시도 ({t + 1}/18)")
                time.sleep(10)
        done = _wait(lambda: ba.get_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id,
                                                  ingestionJobId=job["ingestionJobId"])["ingestionJob"],
                     lambda j: j["status"] in ("COMPLETE", "FAILED"), "수집 작업")
        reasons = " ".join(done.get("failureReasons") or [])
        if done["status"] == "COMPLETE" and not reasons:
            break
        if "307" in reasons or "temporary endpoint" in reasons:
            print(f"  S3 버킷 DNS 전파 대기 중(307) — 30초 뒤 수집 재시도 ({attempt + 1}/8)")
            time.sleep(30)
            continue
        if "not authorized" in reasons or "AccessDenied" in reasons:   # 방금 바꾼 KB 역할 정책이 아직 전파 전
            print(f"  KB 역할 권한 전파 대기 중 — 20초 뒤 수집 재시도 ({attempt + 1}/8)")
            time.sleep(20)
            continue
        raise RuntimeError(done.get("failureReasons"))
    else:
        raise RuntimeError("S3 307 오류가 계속됩니다. 몇 분 뒤 이 셀을 다시 실행하세요. " + reasons)
    ds = {"dataSourceId": ds_id}
    st = done.get("statistics", {})
    save(kb_id=kb_id, kb_id_pending=None, kb_bucket=bucket, kb_vector_bucket=vbucket, kb_index=index, kb_role=f"{PR}-kb-role",
         kb_data_source=ds["dataSourceId"],
         kb_docs_indexed=st.get("numberOfDocumentsScanned"))
    return kb_id


# ---------------------------------------------------------------------------
# 4. AgentCore Runtime 배포
# ---------------------------------------------------------------------------
def discover() -> dict:
    """lab_config.json이 없거나 값이 빠졌을 때, 이름 규칙으로 이 리전의 실습 리소스를 찾아 설정 파일을 다시 만든다.
    (00_setup이 만든 리소스는 모두 ajou-aisec3x-<LAB_SUFFIX> 이름 규칙을 따름)"""
    acct, f = account_id(), {}
    try:
        boto3.client("dynamodb", region_name=REGION).describe_table(TableName=f"{P}-helpdesk")
        f["table"] = f"{P}-helpdesk"
    except Exception:  # noqa: BLE001
        pass
    try:
        f["totp_secret_arn"] = boto3.client("secretsmanager", region_name=REGION).describe_secret(SecretId=f"{P}/totp-seeds")["ARN"]
        f["totp_secret"] = f"{P}/totp-seeds"
    except Exception:  # noqa: BLE001
        pass
    idp = boto3.client("cognito-idp", region_name=REGION)
    pools = [p for p in idp.list_user_pools(MaxResults=60)["UserPools"] if p["Name"] == f"{P}-directory"]
    if pools:
        f["user_pool_id"] = pools[0]["Id"]
        f["user_pool_arn"] = idp.describe_user_pool(UserPoolId=pools[0]["Id"])["UserPool"]["Arn"]
    lg = f"/{P}/login-events"
    if boto3.client("logs", region_name=REGION).describe_log_groups(logGroupNamePrefix=lg)["logGroups"]:
        f["login_log_group"] = lg
    ba = boto3.client("bedrock-agent", region_name=REGION)
    kbs = [k for k in ba.list_knowledge_bases(maxResults=100)["knowledgeBaseSummaries"] if k["name"] == f"{P}-kb"]
    if kbs:
        kb_id = kbs[0]["knowledgeBaseId"]
        dss = ba.list_data_sources(knowledgeBaseId=kb_id)["dataSourceSummaries"]
        f.update(kb_id=kb_id, kb_bucket=f"{P}-kb-{acct}-{REGION}", kb_vector_bucket=f"{P}-vectors", kb_index="helpdesk-kb",
                 kb_role=ba.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["roleArn"].rsplit("/", 1)[-1],
                 kb_data_source=dss[0]["dataSourceId"] if dss else None)
    ctl = boto3.client("bedrock-agentcore-control", region_name=REGION)
    rts = [r for r in ctl.list_agent_runtimes(maxResults=100)["agentRuntimes"] if r["agentRuntimeName"] == f"{PU}_helpdesk"]
    if rts:
        g = ctl.get_agent_runtime(agentRuntimeId=rts[0]["agentRuntimeId"])
        f.update(runtime_id=g["agentRuntimeId"], runtime_arn=g["agentRuntimeArn"], runtime_version=g["agentRuntimeVersion"],
                 runtime_log_group=f"/aws/bedrock-agentcore/runtimes/{g['agentRuntimeId']}-DEFAULT",
                 runtime_role_arn=g["roleArn"], runtime_role=g["roleArn"].rsplit("/", 1)[-1],
                 code_bucket=f"{P}-code-{acct}-{REGION}",
                 model_id=(g.get("environmentVariables") or {}).get("HD_MODEL_ID", "us.amazon.nova-lite-v1:0"))
    try:
        cfgl = boto3.client("lambda", region_name=REGION).get_function(FunctionName=f"{P}-alert-responder")["Configuration"]
        f.update(alert_function=f"{P}-alert-responder", alert_rule=f"{P}-security-alert", alert_role=cfgl["Role"].rsplit("/", 1)[-1])
    except Exception:  # noqa: BLE001
        pass
    if f:
        print(f"↺ {REGION}에서 실습 리소스 {len(f)}개 항목을 찾아 lab_config.json을 다시 만들었습니다"
              f"{' (런타임 포함)' if 'runtime_arn' in f else ' (런타임 없음 → 00_setup 4단계 필요)'}.")
        return save(**f)
    return load()


def ensure_config() -> dict:
    """런타임 배포에 필요한 값이 설정 파일에 다 있는지 확인하고, ID만 있고 ARN이 빠진 값은 AWS에서 다시 채운다."""
    c = load()
    need = {"table": "2단계 create_table()", "totp_secret": "2단계 create_totp_secret()",
            "user_pool_id": "2단계 create_directory()", "login_log_group": "2단계 create_login_events()",
            "kb_id": "3단계 create_knowledge_base()"}
    missing = [f"{k} ← {how}" for k, how in need.items() if not c.get(k)]
    if missing:
        raise RuntimeError("lab_config.json에 다음 값이 없습니다. 00_setup의 해당 셀을 먼저 실행하세요:\n  " + "\n  ".join(missing))
    fix = {}
    if not c.get("user_pool_arn"):
        fix["user_pool_arn"] = boto3.client("cognito-idp", region_name=REGION).describe_user_pool(
            UserPoolId=c["user_pool_id"])["UserPool"]["Arn"]
    if not c.get("totp_secret_arn"):
        fix["totp_secret_arn"] = boto3.client("secretsmanager", region_name=REGION).describe_secret(
            SecretId=c["totp_secret"])["ARN"]
    return save(**fix) if fix else c


def runtime_env() -> dict:
    c = ensure_config()
    return {"HD_REGION": REGION, "HD_USER_POOL_ID": c["user_pool_id"], "HD_TABLE": c["table"],
            "HD_TOTP_SECRET": c["totp_secret"], "HD_KB_ID": c["kb_id"], "HD_LOGIN_LOG_GROUP": c["login_log_group"],
            "HD_MODEL_ID": c.get("model_id", "us.amazon.nova-lite-v1:0")}


def build_package() -> str:
    """agent_runtime/ + 의존성(linux arm64 휠)을 zip으로 묶는다. uv가 필요합니다 (pip install uv)."""
    import shutil
    import subprocess

    build = os.path.join(HERE, "build", "runtime_pkg")
    shutil.rmtree(os.path.dirname(build), ignore_errors=True)
    os.makedirs(build)
    subprocess.run(["uv", "pip", "install", "--quiet", "--target", build, "--python-platform", "aarch64-manylinux2014",
                    "--python-version", "3.12", "--only-binary", ":all:", "-r",
                    os.path.join(HERE, "agent_runtime", "requirements.txt")], check=True)
    for f in ("helpdesk_agent.py", "helpdesk_backend.py"):
        shutil.copy(os.path.join(HERE, "agent_runtime", f), build)
    # Windows에서 설치하면 bin/에 .exe 실행 파일이 생김 → 런타임(Linux)용 스크립트로 바꿈
    bindir = os.path.join(build, "bin")
    shutil.rmtree(bindir, ignore_errors=True)
    os.makedirs(bindir)
    launcher = ["#!/usr/bin/env python3", "import sys",
                "from opentelemetry.instrumentation.auto_instrumentation import run",
                "if __name__ == '__main__':", "    sys.exit(run())", ""]
    with open(os.path.join(bindir, "opentelemetry-instrument"), "wb") as f:
        f.write(chr(10).join(launcher).encode())
    zpath = os.path.join(HERE, "build", "agent.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(build):
            for fn in files:
                full = os.path.join(root, fn)
                arc = os.path.relpath(full, build).replace(os.sep, "/")
                info = zipfile.ZipInfo.from_file(full, arc)
                info.external_attr = (0o755 if arc.startswith("bin/") else 0o644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(full, "rb") as fh:
                    z.writestr(info, fh.read())
    return zpath


def deploy_runtime(model_id: str = "us.amazon.nova-lite-v1:0") -> dict:
    """AgentCore Runtime에 직접 코드 배포 (S3의 zip → create/update_agent_runtime)."""
    acct, c = account_id(), save(model_id=model_id)
    s3 = boto3.client("s3", region_name=REGION)
    ctl = boto3.client("bedrock-agentcore-control", region_name=REGION)
    code_bucket, key = f"{P}-code-{acct}-{REGION}", "helpdesk/agent.zip"
    _create_bucket(s3, code_bucket)
    zpath = build_package()
    s3.upload_file(zpath, code_bucket, key)
    role_name = f"{PR}-runtime-role"
    role_arn = _role(role_name, "bedrock-agentcore.amazonaws.com", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
                                       "logs:DescribeLogStreams", "logs:DescribeLogGroups"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules",
                                       "xray:GetSamplingTargets"], "Resource": "*"},
        {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*",
         "Condition": {"StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}}},
        {"Effect": "Allow", "Action": ["bedrock-agentcore:GetWorkloadAccessToken", "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                                       "bedrock-agentcore:GetWorkloadAccessTokenForUserId"],
         "Resource": f"arn:aws:bedrock-agentcore:{REGION}:{acct}:workload-identity-directory/default*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{code_bucket}/*"}]},
        {"Condition": {"StringEquals": {"aws:SourceAccount": acct},
                       "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock-agentcore:{REGION}:{acct}:*"}}})
    save(code_bucket=code_bucket, runtime_role=role_name, runtime_role_arn=role_arn)
    grant_runtime_role()
    time.sleep(10)   # IAM 전파
    kw = dict(agentRuntimeArtifact={"codeConfiguration": {"code": {"s3": {"bucket": code_bucket, "prefix": key}},
                                                          "runtime": "PYTHON_3_12",
                                                          "entryPoint": ["opentelemetry-instrument", "helpdesk_agent.py"]}},
              roleArn=role_arn, networkConfiguration={"networkMode": "PUBLIC"},
              protocolConfiguration={"serverProtocol": "HTTP"},
              lifecycleConfiguration={"idleRuntimeSessionTimeout": 900, "maxLifetime": 3600},
              environmentVariables=runtime_env(), description="3회차 데모 IT 헬프데스크 에이전트")
    rid = load().get("runtime_id")
    if rid:                      # 저장된 런타임이 이 계정에 없으면 새로 만듦
        try:
            ctl.get_agent_runtime(agentRuntimeId=rid)
        except ctl.exceptions.ResourceNotFoundException:
            print(f"⚠️ 저장된 런타임 {rid}가 이 계정·리전에 없어 새로 만듭니다.")
            rid = None
            save(runtime_id=None, runtime_arn=None, runtime_version=None, runtime_log_group=None)
    if rid:
        ctl.update_agent_runtime(agentRuntimeId=rid, **kw)
    else:
        for attempt in range(6):
            try:
                r = ctl.create_agent_runtime(agentRuntimeName=f"{PU}_helpdesk", **kw)
                break
            except ctl.exceptions.ValidationException as e:   # 역할 전파 전
                if attempt == 5:
                    raise
                time.sleep(10)
        rid = r["agentRuntimeId"]
        save(runtime_id=rid, runtime_arn=r["agentRuntimeArn"])
    st = _wait(lambda: ctl.get_agent_runtime(agentRuntimeId=rid), lambda g: g["status"] in ("READY", "CREATE_FAILED", "UPDATE_FAILED"),
               "런타임 준비", timeout=900, every=10)
    if st["status"] != "READY":
        raise RuntimeError(st.get("failureReason", st["status"]))
    save(runtime_version=st["agentRuntimeVersion"], runtime_log_group=f"/aws/bedrock-agentcore/runtimes/{rid}-DEFAULT")
    return {"runtime_arn": st["agentRuntimeArn"], "version": st["agentRuntimeVersion"], "status": st["status"],
            "package_mb": round(os.path.getsize(zpath) / 1e6, 1)}


def grant_runtime_role() -> None:
    """런타임 실행 역할에 헬프데스크 도구가 쓰는 권한을 붙인다 (툴킷이 만든 기본 권한 + 이 정책)."""
    c, acct = ensure_config(), account_id()
    pol = {"Version": "2012-10-17", "Statement": [
        {"Sid": "Directory", "Effect": "Allow", "Resource": c["user_pool_arn"], "Action": [
            "cognito-idp:AdminGetUser", "cognito-idp:AdminListGroupsForUser", "cognito-idp:AdminEnableUser",
            "cognito-idp:AdminDisableUser", "cognito-idp:AdminSetUserPassword", "cognito-idp:AdminAddUserToGroup",
            "cognito-idp:AdminUpdateUserAttributes"]},
        {"Sid": "Records", "Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query"],
         "Resource": f"arn:aws:dynamodb:{REGION}:{acct}:table/{c['table']}"},
        {"Sid": "Totp", "Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": c["totp_secret_arn"]},
        {"Sid": "Kb", "Effect": "Allow", "Action": "bedrock:Retrieve", "Resource": f"arn:aws:bedrock:{REGION}:{acct}:knowledge-base/{c['kb_id']}"},
        {"Sid": "LoginLogs", "Effect": "Allow", "Action": "logs:FilterLogEvents",
         "Resource": f"arn:aws:logs:{REGION}:{acct}:log-group:{c['login_log_group']}:*"},
        {"Sid": "Models", "Effect": "Allow", "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:ApplyGuardrail"],
         "Resource": "*"}]}
    boto3.client("iam").put_role_policy(RoleName=c["runtime_role"], PolicyName="helpdesk-tools", PolicyDocument=json.dumps(pol))


# ---------------------------------------------------------------------------
# 5. 보안 경보 → EventBridge → Lambda → AgentCore Runtime (범위 4)
# ---------------------------------------------------------------------------
LAMBDA_CODE = r'''
import json, os, boto3
def handler(event, context):
    d = event["detail"]
    sid = ("incident-" + d["incident_id"] + "-" + "0" * 40)[:48]     # runtimeSessionId는 33자 이상
    payload = {"prompt": d["summary"], "requester": "svc:eventbridge/" + event["source"], "scope": d.get("scope", 4),
               "system": "soc", "tools": ["lookup_user", "lock_account", "reset_password", "create_ticket"],
               "audit_level": "continuous", "budget": d.get("budget", 3), "reset": True}
    r = boto3.client("bedrock-agentcore").invoke_agent_runtime(
        agentRuntimeArn=os.environ["RUNTIME_ARN"], runtimeSessionId=sid, payload=json.dumps(payload).encode())
    out = json.loads(r["response"].read())
    boto3.resource("dynamodb").Table(os.environ["TABLE"]).put_item(Item={
        "pk": "SESSION#" + sid, "sk": "RESULT", "text": out.get("text", ""), "stop_reason": out.get("stop_reason", ""),
        "event_id": event["id"], "boto3": boto3.__version__})
    return {"session_id": sid, "stop_reason": out.get("stop_reason")}
'''


def create_alert_pipeline() -> dict:
    c, acct = load(), account_id()
    lam, ev = boto3.client("lambda", region_name=REGION), boto3.client("events", region_name=REGION)
    fn, rule = f"{P}-alert-responder", f"{P}-security-alert"
    role_arn = _role(f"{PR}-alert-lambda", "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "bedrock-agentcore:InvokeAgentRuntime", "Resource": [c["runtime_arn"], c["runtime_arn"] + "/*"]},
        {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": f"arn:aws:dynamodb:{REGION}:{acct}:table/{c['table']}"},
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}]})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("lambda_function.py", LAMBDA_CODE)
    for attempt in range(10):
        try:
            arn = lam.create_function(FunctionName=fn, Runtime="python3.13", Role=role_arn, Handler="lambda_function.handler",
                                      Code={"ZipFile": buf.getvalue()}, Timeout=300, MemorySize=256,
                                      Environment={"Variables": {"RUNTIME_ARN": c["runtime_arn"], "TABLE": c["table"]}})["FunctionArn"]
            break
        except lam.exceptions.ResourceConflictException:   # 이미 있으면 지금 런타임을 가리키도록 갱신
            lam.update_function_configuration(FunctionName=fn, Role=role_arn,
                                              Environment={"Variables": {"RUNTIME_ARN": c["runtime_arn"], "TABLE": c["table"]}})
            arn = lam.get_function(FunctionName=fn)["Configuration"]["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException:   # 역할 전파 대기
            time.sleep(6)
    lam.get_waiter("function_active_v2").wait(FunctionName=fn)
    rule_arn = ev.put_rule(Name=rule, EventPattern=json.dumps({"source": ["ajou.aisec3x.security"], "detail-type": ["Security Alert"]}),
                           State="ENABLED", Description="3회차 데모: 보안 경보 → 헬프데스크 에이전트")["RuleArn"]
    try:
        lam.add_permission(FunctionName=fn, StatementId="events", Action="lambda:InvokeFunction",
                           Principal="events.amazonaws.com", SourceArn=rule_arn)
    except lam.exceptions.ResourceConflictException:
        pass
    ev.put_targets(Rule=rule, Targets=[{"Id": "responder", "Arn": arn}])
    save(alert_function=fn, alert_rule=rule, alert_role=f"{PR}-alert-lambda")
    return {"function": fn, "rule": rule}


# ---------------------------------------------------------------------------
# 정리
# ---------------------------------------------------------------------------
def _try(label, fn, *a, **kw):
    try:
        fn(*a, **kw)
        return f"✅ {label}"
    except Exception as e:  # noqa: BLE001
        return f"⚪ {label}: {type(e).__name__} {str(e)[:80]}"


def _delete_kb(ba, kb_id):
    """KB 삭제: 데이터 원본을 RETAIN으로 바꿔 지운 뒤 KB를 지우고, 삭제가 끝날 때까지 기다림.
    (끝나기 전에 벡터 인덱스나 역할을 지우면 KB 삭제가 DELETE_UNSUCCESSFUL로 멈춤)"""
    for d in ba.list_data_sources(knowledgeBaseId=kb_id)["dataSourceSummaries"]:
        ds = ba.get_data_source(knowledgeBaseId=kb_id, dataSourceId=d["dataSourceId"])["dataSource"]
        ba.update_data_source(knowledgeBaseId=kb_id, dataSourceId=d["dataSourceId"], name=ds["name"],
                              dataSourceConfiguration=ds["dataSourceConfiguration"],
                              vectorIngestionConfiguration=ds["vectorIngestionConfiguration"], dataDeletionPolicy="RETAIN")
        ba.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=d["dataSourceId"])
    time.sleep(5)
    ba.delete_knowledge_base(knowledgeBaseId=kb_id)
    for _ in range(60):
        try:
            st = ba.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"]
        except ba.exceptions.ResourceNotFoundException:
            return
        if st == "DELETE_UNSUCCESSFUL":
            raise RuntimeError("KB 삭제 실패: " + str(ba.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"].get("failureReasons")))
        time.sleep(5)


def _delete_role(name):
    iam = boto3.client("iam")
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    iam.delete_role(RoleName=name)


def cleanup_all(revert_transaction_search: bool = False) -> list[str]:
    c, out = load(), []
    lam, ev = boto3.client("lambda", region_name=REGION), boto3.client("events", region_name=REGION)
    if c.get("alert_rule"):
        out.append(_try("EventBridge 대상", ev.remove_targets, Rule=c["alert_rule"], Ids=["responder"]))
        out.append(_try("EventBridge 규칙", ev.delete_rule, Name=c["alert_rule"]))
    if c.get("alert_function"):
        out.append(_try("Lambda", lam.delete_function, FunctionName=c["alert_function"]))
        out.append(_try("Lambda 역할", _delete_role, c["alert_role"]))
    if c.get("runtime_id"):
        ctl = boto3.client("bedrock-agentcore-control", region_name=REGION)
        out.append(_try("AgentCore Runtime", ctl.delete_agent_runtime, agentRuntimeId=c["runtime_id"]))
        out.append(_try("런타임 실행 역할", _delete_role, c["runtime_role"]))
    if c.get("code_bucket"):
        def del_code():
            b = boto3.resource("s3", region_name=REGION).Bucket(c["code_bucket"]); b.objects.all().delete(); b.delete()
        out.append(_try("런타임 코드 버킷", del_code))
    ba = boto3.client("bedrock-agent", region_name=REGION)
    if c.get("kb_id") or c.get("kb_id_pending"):
        out.append(_try("Knowledge Base", _delete_kb, ba, c.get("kb_id") or c["kb_id_pending"]))
        s3v = boto3.client("s3vectors", region_name=REGION)
        out.append(_try("S3 Vectors 인덱스", s3v.delete_index, vectorBucketName=c["kb_vector_bucket"], indexName=c["kb_index"]))
        out.append(_try("S3 Vectors 버킷", s3v.delete_vector_bucket, vectorBucketName=c["kb_vector_bucket"]))
        s3 = boto3.resource("s3", region_name=REGION)

        def del_bucket():
            b = s3.Bucket(c["kb_bucket"]); b.objects.all().delete(); b.delete()
        out.append(_try("KB 문서 버킷", del_bucket))
        out.append(_try("KB 역할", _delete_role, c["kb_role"]))
    for legacy in (f"{P}-kb-{account_id()}", f"{P}-code-{account_id()}"):   # 예전 이름(리전 없음)으로 남은 버킷
        def del_legacy(name=legacy):
            bk = boto3.resource("s3", region_name=REGION).Bucket(name); bk.objects.all().delete(); bk.delete()
        r = _try(f"예전 이름 버킷 {legacy}", del_legacy)
        if r.startswith("✅"):
            out.append(r)
    if c.get("user_pool_id"):
        out.append(_try("Cognito 사용자 풀", boto3.client("cognito-idp", region_name=REGION).delete_user_pool, UserPoolId=c["user_pool_id"]))
    if c.get("totp_secret"):
        out.append(_try("Secrets Manager 시드", boto3.client("secretsmanager", region_name=REGION).delete_secret,
                        SecretId=c["totp_secret"], ForceDeleteWithoutRecovery=True))
    if c.get("table"):
        out.append(_try("DynamoDB 테이블", boto3.client("dynamodb", region_name=REGION).delete_table, TableName=c["table"]))
    if c.get("login_log_group"):
        out.append(_try("로그인 기록 로그 그룹", boto3.client("logs", region_name=REGION).delete_log_group, logGroupName=c["login_log_group"]))
    if revert_transaction_search and c.get("transaction_search_changed"):
        out.append(_try("Transaction Search 되돌리기", boto3.client("xray", region_name=REGION).update_trace_segment_destination, Destination="XRay"))
    if os.path.exists(CONFIG_PATH):
        os.rename(CONFIG_PATH, CONFIG_PATH + f".deleted-{int(time.time())}")
    return out
