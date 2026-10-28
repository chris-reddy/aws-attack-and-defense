# remediate/raynor_policy_fixed.tf  (representative least-privilege replacement)
resource "aws_iam_policy" "raynor_fixed" {
  name = "cg-raynor-policy-fixed"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ScopedReadOnly"
      Effect   = "Allow"
      Action   = ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"]
      Resource = "*"
      # NOTE: iam:CreatePolicyVersion and iam:SetDefaultPolicyVersion deliberately removed
    }]
  })
}
