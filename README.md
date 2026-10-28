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
- **Remediate** — the fix written as Terraform, with a before/after IAM policy diff.
- **Verify** — the original exploit re-run, now failing with `AccessDenied`.

---

## Scenarios

| # | Scenario | Technique | GuardDuty (native) | Custom detection | Write-up |
| --- | --- | --- | --- | --- | --- |
| 1 | [`iam_privesc_by_rollback`](iam_privesc_by_rollback/) | IAM policy version rollback | ❌ Not detected | ✅ | [Read](writeups/01-iam-privesc-by-rollback.md) |
| 2 | [`iam_privesc_by_attachment`](iam_privesc_by_attachment/) | Instance-profile role swap + `iam:PassRole` | ⚠️ Partial (exfil only) | ✅ | [Read](writeups/02-iam-privesc-by-attachment.md) |

*More scenarios in progress.*

---

## Headline results

- **2** scenarios completed with the full exploit → detect → remediate → verify loop
- **3** MITRE ATT&CK techniques mapped ([T1078](https://attack.mitre.org/techniques/T1078/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1552.005](https://attack.mitre.org/techniques/T1552/005/))
- **2** custom CloudTrail/Athena detections written, with Sigma rule equivalents
- **GuardDuty native coverage:** 0 of 2 privilege-escalation *techniques* detected natively; 1 of 2 scenarios flagged at the credential-exfiltration stage only — demonstrating why custom control-plane detection is required alongside managed tooling
<!-- Prowler before/after critical+high counts: fill in from your scan reports once finalized. -->

---

## Key findings

- **Control-plane privilege escalation hides from behaviour-based detection.**
  GuardDuty missed both IAM privesc techniques. It caught credential
  exfiltration in scenario 2 (the symptom) but not the `AddRoleToInstanceProfile`
  role swap that produced the credentials (the cause). Layered detection —
  native *and* custom — is not optional.
- **`iam:PassRole` on `Resource: "*"` is a critical finding.** It is the quiet
  enabler behind most AWS role-based escalation. Scoping it closes an entire
  attack class.
- **Fixes belong in the permission, not the artifact.** Removing a dangerous
  action is more durable than cleaning up one bad policy version or role.

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
├── remediate/       Terraform fix + before/after IAM policy diff
├── verify/          the exploit re-run, now failing
└── scans/           Prowler posture report
writeups/            narrative incident-report write-ups
setup/               lab build evidence (CloudTrail, GuardDuty, toolchain)
```

---

## A note on safety

This lab runs in a dedicated, isolated AWS account. CloudGoat deliberately
creates vulnerable resources; they are torn down after each scenario. Account
IDs and credentials in screenshots are redacted, and live credential files are
excluded from version control via `.gitignore`.
