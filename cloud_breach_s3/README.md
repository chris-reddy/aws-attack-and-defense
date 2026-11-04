# cloud_breach_s3

**Technique:** SSRF via misconfigured reverse proxy → EC2 metadata credential theft → S3 data exfiltration (the Capital One breach pattern)
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1552.005 (Cloud Instance Metadata API), T1530 (Data from Cloud Storage Object), T1078 (Valid Accounts)

## Summary

Starting as an anonymous outsider with nothing but the IP of an EC2 instance, the
attacker exploits a reverse proxy that forwards requests based on the `Host`
header. Setting `Host: 169.254.169.254` makes the proxy query the instance
metadata service (IMDSv1) and return the EC2 role's credentials. The role carries
`AmazonS3FullAccess`, so the attacker lists and downloads a bucket of sensitive
cardholder data. This is a direct re-creation of the 2019 Capital One breach.

## Attack path

1. Recon the proxy — it forwards upstream requests by `Host` header.
   (`exploit/proxyresponse.jpg`)
2. SSRF with `Host: 169.254.169.254` → the EC2 role name, then its credentials.
   (`exploit/rolename.jpg`, `exploit/rolecredentials.jpg`)
3. Configure the temporary credentials (session token required) and assume the
   role. (`exploit/get_caller_identity_erratic.jpg`)
4. `aws s3 sync` the cardholder-data bucket to the attacker's machine.
   (`exploit/breach.jpg`)

## Root cause

A reverse proxy forwarded attacker-controlled `Host` headers to the metadata
service (IMDSv1, `http_tokens = "optional"`), exposing the EC2 role's
credentials; the role had `AmazonS3FullAccess` over a bucket of sensitive data.

## Detection

The SSRF/metadata read is not logged — detection follows the use of the stolen
credentials. (1) The WAF role making S3 calls (`ListBuckets`, `ListObjects`,
`GetObject`) from an external IP. (2) Bulk `GetObject` reads, after filtering out
AWS-internal callers (Athena's own result-bucket reads dominate an unfiltered
count — a real detection-tuning lesson). Both rely on S3 **data events** enabled
at lab build. (`detect/athenadetect1.jpg`, `detect/athenadetect2.jpg`)

**GuardDuty:** two High findings,
`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` (EC2
instance + S3 bucket) — caught the exfiltration, not the SSRF technique.
(`detect/guardduty1.jpg`)

## Remediation

Enforce IMDSv2 (`http_tokens = "required"`, hop limit 1), which blocks the
token-less SSRF metadata read. (`remediate/remediate.jpg`,
`remediate/metadata_options_fix.tf`) Supporting fixes: fix the proxy's Host
forwarding, scope the role down from `AmazonS3FullAccess`, and lock the S3 bucket
(Block Public Access, least-privilege policy, encryption).

## Verification

Re-ran the SSRF credential grab after enforcing IMDSv2 — the metadata endpoint now
returns nothing to the proxy's token-less GET. The attack path is closed.
(`verify/verify.jpg`)

## Prevention (deploy-time guardrail)

A Checkov/OPA/SCP check requiring `http_tokens = "required"` on every EC2
instance, plus one flagging `AmazonS3FullAccess` on instance roles, would stop
this before it ships.
