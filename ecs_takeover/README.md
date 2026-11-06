# ecs_takeover

**Technique:** Web command injection → container metadata credential theft (task + host roles) → ECS scheduler abuse to relocate a target container → flag
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1552.005 (Cloud Instance Metadata API), T1609 (Container Administration Command), T1613 (Container and Resource Discovery), T1078 (Valid Accounts)

## Summary

A web app passes its input field to a shell (command injection), giving RCE inside
the `vulnsite` container. A privileged `privd` container on the same host can reach
both the ECS task-credential endpoint (`169.254.170.2`) and the host EC2 metadata
service (`169.254.169.254`), yielding two identities: the task role and the far more
powerful ECS-agent instance role. The target `vault` container runs on a *different*
instance the attacker can't `docker exec` into. Because `vault` is a replica
service, the attacker uses the host role to set its instance to `DRAINING`, forcing
ECS to reschedule `vault` onto the attacker-controlled instance — then reads the flag.

## Attack path

1. Command injection in the web app: `; echo 'hello world'`. (`exploit/injection_poc.jpg`)
2. `; docker ps` → `vulnsite` + privileged `privd`. (`exploit/docker_ps.jpg`)
3. Steal task-role creds (`169.254.170.2`) and host instance-role creds
   (`169.254.169.254`) via the privileged container.
   (`exploit/container_creds.jpg`, `exploit/host_creds.jpg`)
4. Enumerate ECS; find `vault` (replica) on a second instance.
   (`exploit/ecs_enum.jpg`)
5. `ecs update-container-instances-state ... --status DRAINING` on the vault's
   instance → ECS reschedules `vault` onto the attacker's instance.
   (`exploit/drain1.jpg`, `exploit/vault_rescheduled.jpg`)
6. `docker exec <vault> cat FLAG.TXT`. (`exploit/the_flag.jpg`)

## Root cause

Command injection in the web app; a privileged container able to reach the host
metadata service and steal the EC2 instance role; no container-to-IMDS isolation;
and an ECS-agent instance role over-permissioned with
`ecs:UpdateContainerInstancesState` (cluster management a node role never needs).

## Detection

Nearly the whole attack is invisible to CloudTrail (in-container/on-host actions and
metadata reads aren't logged); detection follows the stolen creds' API calls. The
smoking gun: `UpdateContainerInstancesState → DRAINING` by the ECS-agent role from an
external IP. (`detect/athena_drain.jpg`) The recon chain (ListClusters → ListTasks →
DescribeTasks by the task role, then the drain) confirms it. (`detect/athena_chain.jpg`)
A tuning note: filtering only `iamadmin` leaves AWS-service noise (ResourceExplorer,
GuardDuty runtime monitoring) — a production rule must also exclude service
principals and key on the external-IP condition. GuardDuty fired HIGH
`UnauthorizedAccess:IAMUser/ResourceCredentialExfiltration.OutsideAWS` on the task
role — catching the credential exfil, not the scheduler-abuse technique.
(`detect/guardduty1.jpg`)

## Remediation

(1) Live: explicit `Deny` on `ecs:UpdateContainerInstancesState` for the ECS-agent
role (`remediate/deny_ecs_drain.json`, `remediate/deny_policy.jpg`). (2) Fix the
command injection (no shell from request input). (3) Stop running privileged
containers. (4) Block containers from `169.254.169.254` to prevent host-role theft
(`remediate/block_container_imds.sh`). (5) Least-privilege all ECS roles.

## Verification

Re-ran the drain with the stolen host creds after the deny → `AccessDenied ...
explicit deny`. The pivot is closed. (`verify/verify.jpg`)

## Prevention (deploy-time guardrail)

SAST for shell-from-input in app code; a policy check that no task/instance role
holds `ecs:UpdateContainerInstancesState`; deny `privileged: true` in task
definitions via admission/Config; and require container-to-IMDS blocking (or
`awsvpc` mode) on every ECS host.
