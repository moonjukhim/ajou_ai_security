"""Demo 1 네트워크 실험: 프라이빗 VPC + AgentCore 인터페이스 엔드포인트 + Memory + VPC 안의 Lambda.

인터넷 게이트웨이·NAT가 없는 VPC에서 Lambda가 AgentCore Memory API를 호출합니다.
가는 길은 인터페이스 엔드포인트 하나뿐이므로, 엔드포인트 정책이 실제로 무엇을 막는지 그대로 보입니다.
"""
from __future__ import annotations

import io
import json
import time
import zipfile

import boto3

import lab_infra as L

REGION, P, PU, PR = L.REGION, L.P, L.PU, L.PR
CIDR = "10.80.0.0/16"

PROBE_CODE = r'''
import json, os, time, uuid, boto3
from botocore.config import Config
CFG = Config(connect_timeout=3, read_timeout=5, retries={"max_attempts": 1})

def handler(event, context):
    mem = os.environ["MEMORY_ID"]
    ac = boto3.client("bedrock-agentcore", config=CFG)
    out = {}
    def run(name, fn):
        try:
            r = fn(); out[name] = {"result": "허용", "detail": r}
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
            msg = str(e)
            if code == "AccessDeniedException":
                out[name] = {"result": "거부", "detail": msg[-160:]}
            elif code in ("ResourceNotFoundException", "ValidationException"):
                out[name] = {"result": "허용", "detail": f"권한 통과 후 {code}"}
            elif "Connect timeout" in msg or "ConnectTimeout" in type(e).__name__ or "EndpointConnectionError" in type(e).__name__:
                out[name] = {"result": "경로 없음", "detail": type(e).__name__}
            else:
                out[name] = {"result": code, "detail": msg[-160:]}
    sid = "probe-" + uuid.uuid4().hex
    ev = {}
    def create():
        r = ac.create_event(memoryId=mem, actorId="emp-1024", sessionId=sid, eventTimestamp=time.time(),
                            payload=[{"conversational": {"content": {"text": "VPN이 안 돼요"}, "role": "USER"}}])
        ev["id"] = r["event"]["eventId"]; return ev["id"]
    run("CreateEvent (대화 기록 쓰기)", create)
    run("ListEvents (대화 기록 읽기)", lambda: len(ac.list_events(memoryId=mem, actorId="emp-1024", sessionId=sid)["events"]))
    run("ListActors (다른 사용자 목록)", lambda: len(ac.list_actors(memoryId=mem)["actorSummaries"]))
    run("DeleteEvent (기록 삭제)", lambda: ac.delete_event(memoryId=mem, actorId="emp-1024", sessionId=sid,
                                                          eventId=ev.get("id", "0" * 10)) and "deleted")
    run("DeleteMemoryRecord (장기 기억 삭제)", lambda: ac.delete_memory_record(memoryId=mem, memoryRecordId="mem-" + "0" * 40))
    br = boto3.client("bedrock-runtime", config=CFG)
    run("Bedrock 모델 호출 (엔드포인트 없음)", lambda: br.converse(modelId="us.amazon.nova-lite-v1:0",
        messages=[{"role": "user", "content": [{"text": "hi"}]}], inferenceConfig={"maxTokens": 5}) and "ok")
    return out
'''


def create_network_lab(slide8_policy_fn) -> dict:
    """VPC, 서브넷 2개, 보안 그룹, AgentCore 엔드포인트(슬라이드 8 정책), Memory, VPC Lambda를 만든다."""
    ec2 = boto3.client("ec2", region_name=REGION)
    ctl = boto3.client("bedrock-agentcore-control", region_name=REGION)
    lam = boto3.client("lambda", region_name=REGION)
    acct = L.account_id()
    t0 = time.time()

    # 1) Memory (엔드포인트 정책의 Resource)
    mem = ctl.create_memory(name=f"{PU}_netlab_{int(time.time()) % 100000}", eventExpiryDuration=7, description="Demo 1 엔드포인트 정책 실험")["memory"]
    mem_id = mem["id"]
    mem_arn = mem.get("arn") or f"arn:aws:bedrock-agentcore:{REGION}:{acct}:memory/{mem_id}"
    L.save(net_memory_id=mem_id)

    # 2) VPC (인터넷 게이트웨이·NAT 없음)
    vpc_id = ec2.create_vpc(CidrBlock=CIDR, TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": f"{P}-netlab"}]}])["Vpc"]["VpcId"]
    L.save(net_vpc_id=vpc_id)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id])
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    svc = ec2.describe_vpc_endpoint_services(ServiceNames=[f"com.amazonaws.{REGION}.bedrock-agentcore"])["ServiceDetails"][0]
    azs = sorted(svc["AvailabilityZones"])[:2]
    subnets = [ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.80.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
               for i, az in enumerate(azs)]
    sg = ec2.create_security_group(GroupName=f"{P}-netlab-sg", Description="HTTPS within VPC only", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                                                                     "IpRanges": [{"CidrIp": CIDR}]}])
    L.save(net_subnets=subnets, net_sg=sg)

    # 3) Lambda 역할 (신원 정책은 넓게 → 막는 것은 엔드포인트 정책뿐임을 보이기 위해)
    role_arn = L._role(f"{PR}-netlab-lambda", "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "bedrock-agentcore:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": "*"},
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
                                       "ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DeleteNetworkInterface",
                                       "ec2:AssignPrivateIpAddresses", "ec2:UnassignPrivateIpAddresses"], "Resource": "*"}]})
    L.save(net_lambda_role=f"{PR}-netlab-lambda", net_lambda_role_arn=role_arn)

    # 4) 인터페이스 엔드포인트 (프라이빗 DNS, 슬라이드 8 정책)
    policy = slide8_policy_fn(acct, mem_arn)
    ep = ec2.create_vpc_endpoint(VpcEndpointType="Interface", VpcId=vpc_id, ServiceName=f"com.amazonaws.{REGION}.bedrock-agentcore",
                                 SubnetIds=subnets, SecurityGroupIds=[sg], PrivateDnsEnabled=True,
                                 PolicyDocument=json.dumps(policy))["VpcEndpoint"]["VpcEndpointId"]
    L.save(net_endpoint_id=ep)

    # 5) VPC 안의 Lambda
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("lambda_function.py", PROBE_CODE)
    fn = f"{P}-netlab-probe"
    for _ in range(12):
        try:
            lam.create_function(FunctionName=fn, Runtime="python3.13", Role=role_arn, Handler="lambda_function.handler",
                                Code={"ZipFile": buf.getvalue()}, Timeout=60, MemorySize=256,
                                VpcConfig={"SubnetIds": subnets, "SecurityGroupIds": [sg]},
                                Environment={"Variables": {"MEMORY_ID": mem_id}})
            break
        except lam.exceptions.InvalidParameterValueException:
            time.sleep(8)          # 역할 전파 대기
    L.save(net_function=fn)

    L._wait(lambda: ctl.get_memory(memoryId=mem_id)["memory"]["status"], lambda s: s == "ACTIVE", "Memory", 600, 10)
    L._wait(lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[ep])["VpcEndpoints"][0]["State"],
            lambda s: s.lower() == "available", "엔드포인트", 600, 10)
    lam.get_waiter("function_active_v2").wait(FunctionName=fn)
    return {"vpc": vpc_id, "subnets": subnets, "azs": azs, "security_group": sg, "endpoint": ep,
            "memory": mem_id, "memory_arn": mem_arn, "lambda": fn, "lambda_role_arn": role_arn, "seconds": round(time.time() - t0)}


def probe() -> dict:
    lam = boto3.client("lambda", region_name=REGION)
    r = lam.invoke(FunctionName=L.load()["net_function"], Payload=b"{}")
    return json.loads(r["Payload"].read())


def set_endpoint_policy(policy: dict) -> None:
    boto3.client("ec2", region_name=REGION).modify_vpc_endpoint(VpcEndpointId=L.load()["net_endpoint_id"],
                                                                PolicyDocument=json.dumps(policy))


def cleanup_network_lab(wait_eni: bool = True) -> list[str]:
    """Lambda → (Lambda ENI 해제 대기) → 엔드포인트 → 보안 그룹 → 서브넷 → VPC → Memory → 역할."""
    c, out = L.load(), []
    ec2 = boto3.client("ec2", region_name=REGION)
    if c.get("net_function"):
        out.append(L._try("Lambda", boto3.client("lambda", region_name=REGION).delete_function, FunctionName=c["net_function"]))
    if c.get("net_endpoint_id"):
        out.append(L._try("인터페이스 엔드포인트", ec2.delete_vpc_endpoints, VpcEndpointIds=[c["net_endpoint_id"]]))
    if c.get("net_vpc_id") and wait_eni:
        t0 = time.time()
        while time.time() - t0 < 1500:   # Lambda가 만든 ENI는 함수 삭제 후 해제되기까지 수 분~20분 걸릴 수 있음
            enis = ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [c["net_vpc_id"]]}])["NetworkInterfaces"]
            for e in enis:
                if e["Status"] == "available":
                    L._try("ENI", ec2.delete_network_interface, NetworkInterfaceId=e["NetworkInterfaceId"])
            if not enis:
                break
            time.sleep(20)
        out.append(f"✅ ENI 정리 ({time.time() - t0:.0f}초)")
    for sn in c.get("net_subnets") or []:
        out.append(L._try(f"서브넷 {sn}", ec2.delete_subnet, SubnetId=sn))
    if c.get("net_sg"):
        out.append(L._try("보안 그룹", ec2.delete_security_group, GroupId=c["net_sg"]))
    if c.get("net_vpc_id"):
        out.append(L._try("VPC", ec2.delete_vpc, VpcId=c["net_vpc_id"]))
    if c.get("net_memory_id"):
        out.append(L._try("Memory", boto3.client("bedrock-agentcore-control", region_name=REGION).delete_memory, memoryId=c["net_memory_id"]))
    if c.get("net_lambda_role"):
        out.append(L._try("Lambda 역할", L._delete_role, c["net_lambda_role"]))
    if all(x.startswith("✅") for x in out):
        L.save(**{k: None for k in ["net_function", "net_endpoint_id", "net_subnets", "net_sg", "net_vpc_id", "net_memory_id", "net_lambda_role"]})
    return out
