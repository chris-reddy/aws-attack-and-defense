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
- **Detect** — the CloudTrail events the attack generated, the Athena query (and Sigma rule) that catches them, and whether GuardDuty saw it natively.
- **Remediate** — the fix written as Terraform, with a before/after diff.
- **Verify** — the original exploit re-run, now failing.

---

## Scenarios

| # | Scenario | Technique | GuardDuty (native) | Custom detection | Write-up |
| --- | --- | --- | --- | --- | --- |
| 1 | [`iam_privesc_by_rollback`](iam_privesc_by_rollback/) | IAM policy version rollback | ❌ Not detected | ✅ | [Read](writeups/01-iam-privesc-by-rollback.md) |
| 2 | [`iam_privesc_by_attachment`](iam_privesc_by_attachment/) | Instance-profile role swap + `iam:PassRole` | ⚠️ Partial (exfil only) | ✅ | [Read](writeups/02-iam-privesc-by-attachment.md) |
| 3 | [`ec2_ssrf`](ec2_ssrf/) | SSRF → instance metadata credential theft | ⚠️ Partial (exfil only) | ✅ | [Read](writeups/03-ec2-ssrf.md) |

*More scenarios in progress.*

---

## Headline results

- **3** scenarios completed with the full exploit → detect → remediate → verify loop
- **5** MITRE ATT&CK techniques mapped ([T1078](https://attack.mitre.org/techniques/T1078/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1190](https://attack.mitre.org/techniques/T1190/), [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1552.005](https://attack.mitre.org/techniques/T1552/005/))
- **Custom CloudTrail/Athena detections for every scenario**, with Sigma rule equivalents
- **GuardDuty native coverage:** 0 of 3 attack *techniques* detected natively; 2 of 3 scenarios flagged only at the credential-exfiltration stage — demonstrating why custom control-plane detection is required alongside managed tooling
<!-- Prowler before/after critical+high counts: fill in from your scan reports once finalized. -->

---

## Key findings

- **Control-plane attacks hide from behaviour-based detection.** GuardDuty missed
  every attack *technique* in this lab. It flagged credential exfiltration in
  scenarios 2 and 3 (the symptom) but never the IAM privesc or the SSRF that
  produced those credentials (the cause). Layered detection — native *and*
  custom — is not optional.
- **`iam:PassRole` on `Resource: "*"` is a critical finding.** It is the quiet
  enabler behind most AWS role-based escalation. Scoping it closes an entire
  attack class.
- **IMDSv2 is not optional.** A single instance attribute
  (`http_tokens = required`) defeats SSRF-based credential theft outright.
- **Some attacks never touch the API log.** SSRF against instance metadata leaves
  no CloudTrail trace — only the *use* of the stolen credentials does. Detection
  has to follow the credential, not the exploit.

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
├── remediate/       Terraform fix + before/after diff
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
