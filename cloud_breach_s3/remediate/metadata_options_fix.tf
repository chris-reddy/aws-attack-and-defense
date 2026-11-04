# Remediation for cloud_breach_s3: enforce IMDSv2 on the reverse-proxy instance.
#
# Root cause: an internet-facing reverse proxy forwarded attacker-controlled Host
# headers to the instance metadata service (IMDSv1, http_tokens = "optional"),
# exposing the EC2 role's credentials. Those credentials (AmazonS3FullAccess) were
# then used to exfiltrate a bucket of sensitive data.
#
# Enforcing IMDSv2 requires a token obtained via PUT before any metadata read —
# which the proxy's blind GET forwarding cannot perform — closing the credential
# theft at its source.

resource "aws_instance" "ec2_vulnerable_proxy_server" {
  # ... existing instance configuration ...

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # was "optional" — enforce IMDSv2
    http_put_response_hop_limit = 1          # was 2 — block proxy/container hops
  }
}

# Supporting fixes (each a real finding in this scenario):
#  1. Fix the reverse proxy so it cannot forward arbitrary Host headers to
#     link-local addresses (block 169.254.169.254).
#  2. Scope the EC2 role down from AmazonS3FullAccess to the one bucket it needs.
#  3. Lock the S3 bucket: Block Public Access, a least-privilege bucket policy,
#     and default encryption (see s3_hardening.tf if you add it).
