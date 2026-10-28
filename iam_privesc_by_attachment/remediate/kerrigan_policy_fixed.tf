# Remediated IAM policy for the 'kerrigan' user (iam_privesc_by_attachment).
#
# Root cause of the original scenario:
#   kerrigan's policy granted iam:PassRole on Resource "*" alongside
#   iam:AddRoleToInstanceProfile and ec2:RunInstances. That combination let
#   her load the privileged 'mighty' role into an instance profile and launch
#   an EC2 instance that inherited mighty's credentials.
#
# Fix:
#   - Remove the instance-profile role-swap actions entirely.
#   - Remove ec2:RunInstances / AssociateIamInstanceProfile / CreateKeyPair.
#   - Scope iam:PassRole from "*" down to a single non-privileged role,
#     conditioned on the EC2 service. This is the linchpin: kerrigan can
#     never pass the 'mighty' role, so the escalation path is closed.

variable "account_id" {
  description = "AWS account ID"
  type        = string
}

variable "cloudgoat_id" {
  description = "CloudGoat scenario suffix"
  type        = string
}

resource "aws_iam_policy" "kerrigan_fixed" {
  name        = "cg-kerrigan-policy-fixed"
  description = "Least-privilege replacement for cg-kerrigan-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyIamEc2"
        Effect = "Allow"
        Action = [
          "iam:ListInstanceProfiles",
          "iam:ListRoles",
          "ec2:DescribeIamInstanceProfileAssociations",
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs"
        ]
        Resource = "*"
      },
      {
        Sid      = "PassOnlyNonPrivilegedRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::${var.account_id}:role/cg-ec2-meek-role-${var.cloudgoat_id}"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ec2.amazonaws.com"
          }
        }
      }
    ]
  })
}
