# vulnerable_lambda

**Technique:** SQL injection in a Lambda policy-applier → IAM privilege escalation to admin → Secrets Manager exfiltration
**MITRE ATT&CK:** T1078 (Valid Accounts), T1190 (Exploit Public-Facing Application), T1098.003 (Additional Cloud Roles), T1555.006 (Cloud Secrets Management Stores)

## Summary

Starting as the low-privilege IAM user `bilbo` (assume-one-role + read-only IAM),
the attacker assumes a `lambda-invoker` role, downloads a Lambda that applies IAM
policies from caller input, and finds it builds a SQL query by string-interpolating
that input. A payload of `AdministratorAccess' -- ` comments out the query's
`public='True'` guard — the clause meant to prevent applying admin — so the Lambda
attaches `AdministratorAccess` to `bilbo`. Now admin, the attacker reads the target
secret from Secrets Manager.

## Attack path

1. As `bilbo`, read own permissions: assume-role on `cg-lambda-invoker*` + IAM read.
   (`exploit/bilbo_perms.jpg`)
2. Assume the invoker role; configure temp creds as a second profile.
   (`exploit/assume_role1.jpg`)
3. Download and read the Lambda — SQL built via f-string from input.
   (`exploit/handler.jpg`)
4. Invoke with `{"policy_names": ["AdministratorAccess' -- "], "user_name": "cg-bilbo-..."}`
   → admin attached. (`exploit/admin_confirmed.jpg`)
5. Read the secret from Secrets Manager. (`exploit/the_secret.jpg`)

## Root cause

A Lambda builds a SQL statement by interpolating untrusted input (SQL injection),
and its execution role holds `iam:AttachUserPolicy` on `*` with no restriction on
which managed policy it may attach — so the injection escalates to
`AdministratorAccess`.

## Detection

`lambda:Invoke` is a data event (off by default), so the attack is caught by its
side effect: a `AttachUserPolicy` granting `AdministratorAccess`, performed by a
**Lambda execution role** — a compute role modifying IAM user policies.
(`detect/athena_privesc.jpg`) The non-admin chain AssumeRole → AttachUserPolicy →
GetSecretValue tells the rest. (`detect/athena_chain.jpg`) GuardDuty: see write-up.

## Remediation

(1) Root cause: parameterize the query so input is a bound value, not SQL syntax
(`remediate/policy_applier_fixed.py`). (2) Live compensating control: an explicit,
condition-scoped deny (`iam:PolicyARN = AdministratorAccess`) on the Lambda's
execution role, so it can never attach admin even if injected.
(`remediate/deny_policy.jpg`)

## Verification

Detached admin, re-ran the same injection → the Lambda's attach call returned
`AccessDenied ... explicit deny`, the function errored, and `bilbo` has no
`AdministratorAccess`. (`verify/verify2.jpg`)

## Prevention (deploy-time guardrail)

Static analysis for string-built SQL in Lambda source; an IAM policy check that no
function execution role may hold `iam:AttachUserPolicy`/`PutUserPolicy` without an
`iam:PolicyARN` condition; and an SCP denying attachment of `AdministratorAccess`
by any non-human principal.
