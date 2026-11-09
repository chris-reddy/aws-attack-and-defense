# AWS Attack & Defense Lab

A hands-on cloud security lab where each scenario is **exploited, detected,
remediated as code, and verified** — end to end. The focus is the defender's
job: not just breaking in, but catching the attack in logs, fixing the root
cause as infrastructure-as-code, and proving the fix holds.

Built with **CloudGoat** (vulnerable environments), **AWS CLI** and **Pacu**
(offense), **CloudTrail → Athena** and **GuardDuty** (detection), **Terraform**
(remediation), and **Prowler** (posture).

---

## Why this repo is different

Most CloudGoat walkthroughs stop at the exploit. Every scenario here runs the
full loop:

**Exploit → Detect → Remediate → Verify**

- **Exploit** — the attack path, with the exact commands and the misconfiguration behind it.
- **Detect** — the CloudTrail events the attack generated, the Athena query that catches them, and whether GuardDuty saw it natively.
- **Remediate** — the fix written as Terraform/IAM, with a before/after diff.
- **Verify** — the original exploit re-run, now failing.

---

## Scenarios

| # | Scenario | Technique | GuardDuty (native) | Custom detection | Write-up |
| --- | --- | --- | --- | --- | --- |
| 1 | [`iam_privesc_by_rollback`](iam_privesc_by_rollback/) | IAM policy version rollback | ❌ Not detected | ✅ | [Read](writeups/01-iam-privesc-by-rollback.md) |
| 2 | [`iam_privesc_by_attachment`](iam_privesc_by_attachment/) | Instance-profile role swap + `iam:PassRole` | ⚠️ Partial (exfil only) | ✅ | [Read](writeups/02-iam-privesc-by-attachment.md) |
| 3 | [`ec2_ssrf`](ec2_ssrf/) | SSRF → instance metadata credential theft | ⚠️ Partial (exfil only) | ✅ | [Read](writeups/03-ec2-ssrf.md) |
| 4 | [`cloud_breach_s3`](cloud_breach_s3/) | Reverse-proxy SSRF → metadata → S3 data breach | ⚠️ Partial (exfil only) | ✅ | [Read](writeups/04-cloud-breach-s3.md) |
| 5 | [`codebuild_secrets`](codebuild_secrets/) | CodeBuild secret leak → RDS snapshot exfiltration | ❌ Not detected | ✅ | [Read](writeups/05-codebuild-secrets.md) |
| 6 | [`vulnerable_lambda`](vulnerable_lambda/) | SQL injection in Lambda → IAM privesc → Secrets Manager | ❌ Not detected | ✅ | [Read](writeups/06-vulnerable-lambda.md) |
| 7 | [`ecs_takeover`](ecs_takeover/) | Container injection → metadata creds → ECS scheduler abuse | ⚠️ Partial (cred exfil) | ✅ | [Read](writeups/07-ecs-takeover.md) |

---

## Headline results

- **7** scenarios completed with the full exploit → detect → remediate → verify loop
- **10** MITRE ATT&CK techniques mapped ([T1078](https://attack.mitre.org/techniques/T1078/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1190](https://attack.mitre.org/techniques/T1190/), [T1530](https://attack.mitre.org/techniques/T1530/), [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1552.005](https://attack.mitre.org/techniques/T1552/005/), [T1555.006](https://attack.mitre.org/techniques/T1555/006/), [T1578.001](https://attack.mitre.org/techniques/T1578/001/), [T1609](https://attack.mitre.org/techniques/T1609/), [T1613](https://attack.mitre.org/techniques/T1613/))
- **Custom CloudTrail/Athena detections for every scenario**, plus a Sigma rule for the IAM privesc detection
- **GuardDuty native coverage:** 0 of 7 attack *techniques* detected natively; 4 of 7 scenarios flagged at all, and in every case only at the credential/data-exfiltration stage — never the technique itself — demonstrating why custom control-plane detection is required alongside managed tooling

---

## Key findings

- **Control-plane attacks hide from behaviour-based detection.** GuardDuty missed
  every attack *technique* in this lab — IAM privesc, SSRF, and RDS snapshot
  exfiltration all passed it by. It flagged only downstream credential/data
  exfiltration in four scenarios. Layered detection — native *and* custom — is
  not optional.
- **IMDSv2 is not optional.** A single instance attribute
  (`http_tokens = required`) defeats SSRF-based credential theft — the exact class
  of attack behind the Capital One breach (scenario 4).
- **`iam:PassRole` on `*` and `rds:CreateDBSnapshot` are quiet escalation
  primitives.** PassRole enables most role-based privesc; snapshot/restore lets an
  attacker clone a database they can't log into. Scope both.
- **Injection reaches the control plane.** A Lambda that built a SQL query from
  user input escalated a near-powerless user to account admin (scenario 6). Its
  execution role could attach *any* managed policy; one `iam:PolicyARN` condition
  would have stopped it. Parameterize queries and scope what service roles can grant.
- **Attackers recruit reliability features.** In scenario 7, the ECS service
  scheduler's guarantee to keep a replica running became a *placement oracle*:
  draining a node forced the target container to reschedule onto an attacker-owned
  host. A privileged container (reaching the host IMDS) and an over-broad
  `ecs:UpdateContainerInstancesState` permission made it possible — both avoidable.
- **Detection is a noise problem.** Several detections only became useful after
  filtering out legitimate service/admin traffic. Real detection engineering is
  as much about suppressing false positives as finding the signal.

---

## Lab architecture

Every scenario runs against a logging pipeline stood up before any attack:

- **CloudTrail** — multi-region trail capturing management events **and** S3 data events, delivered to a locked-down S3 bucket.
- **Athena** — SQL queries over the CloudTrail logs; the backbone of every custom detection.
- **GuardDuty** — enabled for native threat detection, used as the baseline to measure custom detections against.
- **AWS Budgets** — cost guardrail so the lab stays cheap.

Setup evidence is in [`setup/`](setup/).

---

## Repository layout

```
<scenario>/
├── README.md        scenario summary, attack path, root cause, ATT&CK mapping
├── exploit/         commands + screenshots of the attack succeeding
├── detect/          Athena queries, Sigma rules, GuardDuty findings
├── remediate/       Terraform/IAM fix + before/after diff
├── verify/          the exploit re-run, now failing
└── scans/           Prowler posture report
writeups/            narrative incident-report write-ups
setup/               lab build evidence (CloudTrail, GuardDuty, toolchain)
```

---

## A note on safety

This lab runs in a dedicated, isolated AWS account. CloudGoat deliberately
creates vulnerable resources; they are torn down after each scenario. Account
IDs, credentials, and source IPs in screenshots are redacted, and live
credential files are excluded from version control via `.gitignore`.
