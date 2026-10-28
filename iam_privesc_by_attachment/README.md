# iam_privesc_by_attachment

**Technique:** Privilege escalation via EC2 instance-profile role swap + `iam:PassRole`
**MITRE ATT&CK:** T1078 (Valid Accounts), T1098 (Account Manipulation), T1552.005 (Cloud Instance Metadata API)

## Summary

The scenario starts with credentials for a low-privilege IAM user, `kerrigan`,
who cannot even enumerate her own policies. The environment contains two EC2
roles — `cg-ec2-meek-role` (low privilege) and `cg-ec2-mighty-role` (high
privilege) — and a running EC2 instance. `kerrigan` holds a combination of
permissions that lets her load the privileged `mighty` role into an instance
profile, launch an EC2 instance she controls, and read the `mighty` role's
temporary credentials from the instance metadata service — escalating from a
near-blind user to a privileged role.

## Attack path

1. Confirm starting identity as `kerrigan`; most IAM read calls are denied.
   (`exploit/s2_getcalleridentity.jpg`)
2. Enumerate what is reachable: `list-roles`, `list-instance-profiles`,
   `describe-instances`, subnets and security groups. Discover the `meek` and
   `mighty` roles, the `meek` instance profile, and a running instance with no
   profile attached.
   (`exploit/s2_listroles.jpg`, `exploit/s2_listinstanceprofiles.jpg`,
   `exploit/s2_describeinstances.jpg`, `exploit/describe_sgandsubnets.jpg`)
3. Repackage the `meek` instance profile: remove the `meek` role, add the
   `mighty` role. This is the core escalation primitive.
   (`exploit/s2_repackageinstanceprofiles.jpg`)
4. Create a key pair, then launch a new EC2 instance with the (now
   mighty-carrying) instance profile attached.
   (`exploit/s2_keycreation.jpg`, `exploit/runinstances1.jpg`,
   `exploit/runinstances2.jpg`)
5. SSH into the attacker-controlled instance and read the `mighty` role's
   credentials from the metadata service (IMDSv2).
   (`exploit/credentialblob.jpg`)
6. Confirm escalation: operate as the `mighty` role, which `kerrigan` could
   not do.
   (`exploit/s2_getcalleridentity_escalated.jpg`,
   `exploit/mightyvsmeekroles.jpg`)

## Root cause

`kerrigan` was granted a dangerous **combination** on `Resource: "*"`:
`iam:AddRoleToInstanceProfile`, `iam:RemoveRoleFromInstanceProfile`,
`iam:PassRole`, `ec2:RunInstances`, and `ec2:AssociateIamInstanceProfile`.
`iam:PassRole` on `"*"` is the linchpin — it lets her pass *any* role,
including the privileged `mighty` role, to an EC2 instance.
(`remediate/policybefore.jpg`)

## Detection

CloudTrail shows the escalation as a short sequence from a single non-admin
principal: `RemoveRoleFromInstanceProfile` + `AddRoleToInstanceProfile`
(role swap) immediately followed by `RunInstances`. Individually each event is
ordinary admin activity; chained together by `kerrigan` in minutes, it is
privilege escalation. The Athena query isolates this sequence.
(`detect/s2_detect.jpg`, Athena query in `detect/`)

**GuardDuty:** fired a **High**-severity finding
`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
("Credentials for instance role cg-ec2-mighty-role were used from an external
IP"). Note what it caught vs. missed: GuardDuty detected the **downstream
credential exfiltration** (the mighty creds used off-instance) but **not** the
`AddRoleToInstanceProfile` privilege-escalation technique itself. Native
detection caught the symptom; the custom CloudTrail/Athena detection caught the
root-cause action. Layered detection is why both matter.
(`detect/guardduty_findings.jpg`, `detect/guardduty_details1.jpg`,
`detect/guardduty_details2.jpg`, `detect/guardduty_details3.jpg`)

## Remediation

Removed the instance-profile role-swap actions and the EC2 launch actions, and
scoped `iam:PassRole` from `"*"` down to a single non-privileged role with a
condition restricting it to the EC2 service. Scoping `PassRole` is the key fix:
even with other permissions, `kerrigan` can never pass the `mighty` role.
(`remediate/policybefore.jpg`, `remediate/diff.jpg`,
`remediate/policy_before.json`, `remediate/policy_fixed_after.json`,
`remediate/kerrigan_policy_fixed.tf`)

> Fix applied to the live policy via the CLI (`create-policy-version
> --set-as-default`) for in-lab verification. The Terraform file is the
> production-ready representation; it is not applied into CloudGoat's own
> managed state.

## Verification

Re-ran the core exploit step (`add-role-to-instance-profile`) as `kerrigan`
after applying the fix — now returns **AccessDenied**. The escalation path is
closed. (`verify/verify.jpg`)

## Prevention (deploy-time guardrail)

A Checkov / OPA / SCP rule that denies `iam:PassRole` on `Resource: "*"`, and
flags any policy granting `iam:AddRoleToInstanceProfile` to a non-admin
principal, would stop this misconfiguration before it ships.
