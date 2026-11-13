# 2회차 AWS 방어 데모 — 생성형 AI 보안 위협과 AI 에이전트 보안

`../demos`의 공격 데모(Demo 1~3)를 **AWS 관리형 서비스로 방어**하는 짝 데모입니다. 같은 공격 문장과 시나리오를 사용하므로 “로컬 방어층 vs AWS 서비스”를 바로 비교할 수 있습니다.

| 파일 | 세션 | 짝 데모 | 사용 서비스 | 소요 |
|---|---|---|---|---|
| `aws_demoA_guardrails_prompt_injection.ipynb` | 18:00 프롬프트 인젝션·탈옥 | Demo 1 | Bedrock Guardrails (프롬프트 공격 필터·거부 주제·정규식·PII), Converse 입력 태깅, 모델 호출 로깅 | 12–15분 |
| `aws_demoB_misuse_provenance_phishing.ipynb` | 19:00 AI 사회공학·생성 콘텐츠 | Demo 2 | Bedrock Guardrails (피싱·사칭 거부 주제), Nova Canvas + C2PA, Route 53 Resolver DNS Firewall | 12–15분 |
| `aws_demoC_agent_authorization.ipynb` | 20:00 AI 에이전트 보안 | Demo 3 | Bedrock Guardrails (도구 결과 검사), Amazon Verified Permissions (Cedar) | 12–15분 |
| `aws_demoD_agentcore_identity_2lo_3lo.ipynb` | 20:00 AI 에이전트 보안 (보충) | Demo 3 | AgentCore Identity (워크로드 아이덴티티, OAuth2 자격 증명 공급자 2LO·3LO, 토큰 볼트), Cognito(실습용 IdP) | 12–15분 |
| `aws_common.py` | 공통 모듈 (노트북과 같은 폴더) | | 가드레일 생성·검사·삭제, 표 출력 | |

## 준비
```bash
pip install -r requirements.txt
aws configure            # 또는 aws sso login
export AWS_REGION=us-west-2          # 기본값
export CANVAS_REGION=us-east-1       # Demo B 이미지 생성 리전
export DEMO_MODEL=us.anthropic.claude-haiku-4-5-20251001-v1:0   # Demo A 선택 셀
export DEMO_VPC_ID=vpc-xxxx          # Demo B DNS Firewall을 실습 VPC에 연결할 때만
```
- **Bedrock 모델**: 별도 활성화 없이 처음 호출할 때 자동으로 켜집니다(콘솔의 Model access 페이지는 폐지됨). 필요한 것은 IAM 권한 `bedrock:InvokeModel`뿐입니다.
  - Demo B(Amazon Nova Canvas, us-east-1): 추가 절차 없음
  - Demo A 선택 셀(Claude Haiku 4.5): 계정에서 Anthropic 모델을 처음 쓰면 콘솔 플레이그라운드에서 사용 목적(use case) 양식을 한 번 제출해야 할 수 있음
- **가드레일 티어**: 한국어 탐지를 위해 기본값 `GUARDRAIL_TIER=STANDARD`(교차 리전 프로필 `us.guardrail.v1:0`). 실패하면 자동으로 Classic으로 만들고 경고합니다. Classic은 한국어 탐지율이 낮습니다.

### 필요한 IAM 권한 (실습 계정 기준)
`iam-policy.json`을 노트북 실행 역할(SageMaker·EC2 역할 등)에 인라인 정책으로 붙이세요. `AccessDeniedException ... no identity-based policy allows` 오류가 나면 이 정책이 빠진 것입니다.
```bash
# 관리자 권한이 있는 곳(CloudShell 등)에서 실행. 노트북 역할 자신은 보통 IAM 수정 권한이 없습니다.
aws iam put-role-policy --role-name <노트북-역할-이름> \
  --policy-name ajou-ai-sec-demos --policy-document file://iam-policy.json
```
```
bedrock:CreateGuardrail, CreateGuardrailVersion, GetGuardrail, ListGuardrails, DeleteGuardrail,
bedrock:ApplyGuardrail, bedrock:InvokeModel, bedrock:GetModelInvocationLoggingConfiguration,
verifiedpermissions:CreatePolicyStore, CreatePolicy, IsAuthorized, DeletePolicyStore,
route53resolver:CreateFirewallDomainList, UpdateFirewallDomains, CreateFirewallRuleGroup, CreateFirewallRule,
route53resolver:AssociateFirewallRuleGroup, DisassociateFirewallRuleGroup, ListFirewallRuleGroupAssociations,
route53resolver:DeleteFirewallRule, DeleteFirewallRuleGroup, DeleteFirewallDomainList, sts:GetCallerIdentity
```

## 비용과 정리
- 모든 리소스 이름은 `ajou-ai-sec-`로 시작합니다. **각 노트북의 마지막 셀이 정리 셀**입니다.
- 정리 셀을 못 돌렸다면: `python -c "import aws_common as a; a.delete_guardrails()"` (가드레일 전부), Verified Permissions 정책 저장소와 DNS Firewall은 콘솔에서 `ajou-ai-sec` 로 검색해 삭제.
- 가드레일·인가 요청은 사용량 과금이며 노트북 1회 실행은 소액입니다. Nova Canvas 이미지 1장 생성 비용이 추가됩니다.

## 진행 팁
1. **로컬 데모 먼저, AWS 데모 다음.** Demo 1에서 키워드 필터가 뚫리는 걸 본 뒤, 같은 공격을 Guardrails에 넣어 비교합니다.
2. 결과 셀을 실행하기 전에 예측을 받으세요. (“B2 ‘마감을 무시하면?’은 막힐까?”, “사람이 승인해도 외부 발송이 될까?”)
3. 가드레일 결과는 서비스 업데이트에 따라 달라질 수 있습니다. **실행 결과 표 그대로** 설명하고, 통과한 공격이 있으면 “그래서 출력 검사·설계 변경이 필요하다”로 연결하세요.
4. 네트워크·권한 문제가 생기면 `../demos`의 sim 모드 노트북으로 개념을 설명하고, 이 폴더의 코드는 화면으로만 보여줘도 됩니다.

## 변형 실험 (학생 과제)
- Demo A: 거부 주제 예시 문장을 바꿔 A8(형식 변형)을 막아 보기 / `prompt_attack="MEDIUM"`과 오차단 비교
- Demo B: 1-1(입력 차단)과 1-2(입력 감지 + 응답 차단)의 일치 수 비교 / `RESPONSES`의 E 응답에 예시 메시지를 섞으면 어떻게 되는지 확인 / 예시에 없는 악용 유형(M5)을 직접 만들어 일반화 확인
- Demo C: Cedar 정책 P5 추가 — “내부 주소라도 본문에 전화번호 패턴이 있으면 발송 금지” (context에 `has_pii` 추가)

## 주의 (윤리)
공격 문장은 가짜 비밀 코드와 가상의 학생 데이터만 대상으로 합니다. 실습은 **본인 소유의 AWS 계정**에서만 진행하고, 타인의 서비스에 공격을 시도하지 않도록 안내하세요.
