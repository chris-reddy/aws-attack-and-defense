# ec2_ssrf

**Technique:** SSRF → EC2 instance metadata credential theft (IMDSv1)
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1552.005 (Cloud Instance Metadata API), T1552.001 (Credentials in Files), T1078 (Valid Accounts)

## Summary

Starting as the low-privilege user `solus` (`lambda:Get*`/`List*` only), the
attacker chains four identities together to reach the objective. A set of AWS
keys hardcoded in a Lambda function's environment variables provides the pivot
to `wrex` (`ec2:*`), who locates a web app running on an EC2 instance. The app
is vulnerable to server-side request forgery; because the instance runs with
IMDSv1 enabled (`http_tokens = "optional"`), the SSRF is used to read the EC2
role's credentials from the instance metadata service. Those credentials
(`s3:*`) read a secret bucket containing `shepard`'s keys, and `shepard` invokes
the target Lambda "for the win."

## Attack path

1. `solus` reads the Lambda; its env vars leak `wrex`'s access keys.
   (`exploit/env_variables.jpg`)
2. `wrex` (`ec2:*`) finds the EC2 instance and its public web app.
   (`exploit/describeinstanceswrex.jpg`)
3. SSRF the metadata endpoint via the app's `url=` parameter → steal the
   `cg-ec2-role` credentials. (`exploit/metadatacredentials.jpg`)
4. The EC2 role (`s3:*`) reads the secret bucket → `shepard`'s credentials.
5. `shepard` invokes the Lambda → "You win!". (`exploit/youwin.jpg`)

## Root cause

The headline is a single instance attribute: **`http_tokens = "optional"`**
(IMDSv1 enabled), which lets an unauthenticated SSRF GET read instance
credentials. Supporting misconfigurations: hardcoded credentials in the Lambda
environment, an over-permissive EC2 role (`s3:*`), and an unrestricted
URL-fetching web app.

## Detection

The SSRF and metadata read are not logged by CloudTrail — detection follows the
*use* of the stolen credentials. Two Athena detections: (1) the `cg-ec2-role`
making API calls from an external IP (it should only call from the instance),
and (2) a single source IP associated with multiple distinct principals
(credential-hopping). (`detect/athenadetect1.jpg`, `detect/athenadetect2.jpg`)

**GuardDuty:** two High findings,
`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — it
caught the credential exfiltration (symptom) but not the SSRF technique (cause).
(`detect/guardduty1.jpg`)

## Remediation

Enforce IMDSv2 (`http_tokens = "required"`, hop limit 1), which blocks token-less
SSRF metadata reads. (`remediate/remediate.jpg`,
`remediate/metadata_options_fix.tf`) Supporting fixes: move Lambda secrets to an
IAM role, scope the EC2 role down from `s3:*`, and block link-local requests in
the app.

## Verification

Re-ran the SSRF credential grab after enforcing IMDSv2 — the metadata endpoint
now returns `401 Unauthorized` to the app's token-less GET, so the app reports it
"could not find" the credentials. The attack path is closed. (`verify/verify.jpg`)

## Prevention (deploy-time guardrail)

A Checkov/OPA/SCP check requiring `http_tokens = "required"` on every EC2
instance, and one flagging plaintext credentials in Lambda environment
variables, would stop this misconfiguration before it ships.
