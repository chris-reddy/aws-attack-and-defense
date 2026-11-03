# Remediation for ec2_ssrf: enforce IMDSv2 on the vulnerable instance.
#
# Root cause: the instance ran with http_tokens = "optional" (IMDSv1), letting a
# plain SSRF GET read instance credentials from 169.254.169.254. Enforcing IMDSv2
# requires a token obtained via PUT before any metadata read — which a basic SSRF
# cannot perform — closing the credential-theft path.

resource "aws_instance" "ubuntu_ec2" {
  # ... existing instance configuration ...

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # was "optional" — enforce IMDSv2
    http_put_response_hop_limit = 1          # was 2 — block proxy/container hops
  }
}
