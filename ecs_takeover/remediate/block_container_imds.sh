#!/usr/bin/env bash
# Block containers from reaching the EC2 Instance Metadata Service (IMDS).
#
# Root-cause mitigation for the CloudGoat `ecs_takeover` scenario: a privileged
# container reached 169.254.169.254 and stole the HOST's EC2 instance role
# (the ECS agent role), which could then drain cluster nodes.
#
# This iptables rule, run on each ECS container host, drops traffic from the
# docker bridge network to the instance metadata endpoint, so containers can
# only ever reach their own ECS task-credential endpoint (169.254.170.2),
# never the host's identity.
#
# NOTE: adjust the interface/subnet to match your Docker bridge (docker0 /
# 172.17.0.0/16 is the common default). A cleaner alternative is to run tasks
# in `awsvpc` network mode, which isolates task networking from the host by design.

set -euo pipefail

# Drop packets from the docker bridge subnet to the IMDS address.
iptables -I DOCKER-USER -i docker0 -d 169.254.169.254 -j DROP

# Persist across reboots (Amazon Linux example):
#   iptables-save > /etc/sysconfig/iptables

echo "Containers on docker0 can no longer reach 169.254.169.254 (host IMDS)."
