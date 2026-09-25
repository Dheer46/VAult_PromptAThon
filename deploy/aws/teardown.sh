#!/usr/bin/env bash
# Terminates every instance tagged Project=vault-demo. VPC/SG/buckets are left for you to
# delete (aws ec2 delete-vpc ..., aws s3 rb s3://... --force) so nothing is removed by surprise.
set -euo pipefail
REGION=${REGION:-ap-south-1}
IDS=$(aws ec2 describe-instances --region "$REGION" \
  --filters Name=tag:Project,Values=vault-demo Name=instance-state-name,Values=pending,running,stopped \
  --query 'Reservations[].Instances[].InstanceId' --output text)
[ -n "$IDS" ] && aws ec2 terminate-instances --region "$REGION" --instance-ids $IDS
echo "terminated: $IDS"
