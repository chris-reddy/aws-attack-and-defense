# codebuild_secrets

**Technique:** CodeBuild environment-variable credential leak → IAM pivot → RDS snapshot exfiltration
**MITRE ATT&CK:** T1552.001 (Credentials in Files), T1078 (Valid Accounts), T1578.001 (Create Snapshot), T1530 (Data from Cloud Storage Object)

## Summary

Starting as the IAM user `Solo` (CodeBuild read access only), the attacker reads a
build project whose environment variables leak the IAM keys of a second user,
`Calrissian`, in plaintext. Calrissian can see — but not directly read — a private
RDS Postgres database. Unable to connect, she snapshots it, restores the snapshot
as a new publicly-accessible instance she controls, resets the master password,
and reads a pair of secret strings. This is database exfiltration via snapshot
(MITRE T1578.001) — stealing a database you have no login to.

## Attack path

1. `Solo` reads the CodeBuild project → Calrissian's AWS keys in plaintext env vars.
   (`exploit/batchgetprojects.jpg`)
2. As `Calrissian`, describe the RDS instance — visible but `PubliclyAccessible: false`.
   (`exploit/describe-db-instances.jpg`)
3. Snapshot it → restore the snapshot as a public instance → reset the master
   password. (`exploit/restore.jpg`)
4. Connect with `psql` and read the secrets. (`exploit/sensitiveinfo.jpg`)

> Networking note: `PubliclyAccessible: true` did not make the restored DB
> internet-reachable — its subnet group had no internet-gateway route, so it was
> only reachable from inside the VPC, requiring a pivot through an in-VPC EC2 host.

## Root cause

Plaintext credentials in a CodeBuild environment variable; `Calrissian`
over-permissioned with `rds:CreateDBSnapshot` / `RestoreDBInstanceFromDBSnapshot`;
and no control preventing a restored instance from being made publicly accessible.

## Detection

A short, high-signal CloudTrail sequence from the non-admin users: `Solo` →
`BatchGetProjects`, then `Calrissian` → `CreateDBSnapshot` →
`RestoreDBInstanceFromDBSnapshot` (with `PubliclyAccessible: true`) →
`ModifyDBInstance` (password reset). Filtering out the account admin isolates the
attack. (`detect/detect.jpg`) GuardDuty produced zero findings for the entire
chain (`detect/guardduty.jpg`) — no native coverage of this control-plane technique.

## Remediation

Applied live: an explicit `Deny` on `rds:CreateDBSnapshot` /
`RestoreDBInstanceFromDBSnapshot` / `ModifyDBInstance` for `Calrissian`.
(`remediate/remediate.jpg`) Fuller fix: move CodeBuild secrets into the build
service role + Secrets Manager, scope Calrissian to least privilege, block public
RDS via SCP/Config, and encrypt snapshots with a customer-managed KMS key.

## Verification

Re-ran `create-db-snapshot` as Calrissian after the deny → `AccessDenied`. The
exfiltration primitive is closed. (`verify/verify.jpg`)

## Prevention (deploy-time guardrail)

Checkov/OPA/SCP checks: no plaintext credentials in CodeBuild environment
variables, deny `PubliclyAccessible=true` on RDS, and require customer-managed KMS
encryption on RDS instances and snapshots.
