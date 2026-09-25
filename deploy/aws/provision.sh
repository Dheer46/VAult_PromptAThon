#!/usr/bin/env bash
# Phase 18 — Budget layout on AWS EC2 (single AZ; survives node and drive failures):
#   4 storage nodes (t3.large) x 4 gp3 volumes = 16 drives = 2 sets of 8, EC 5+3
#   1 services node: KMS Provider, Keystone + MariaDB, Kafka, webhook, Prometheus, Grafana, HAProxy
#   Remote S3 = real S3 buckets in another region (replication + lifecycle tier).
#
# Usage: REGION=ap-south-1 REMOTE_REGION=ap-southeast-1 KEY_NAME=my-key MY_IP=1.2.3.4/32 ./provision.sh
# Tear down with ./teardown.sh. Set an AWS Budgets alert before running this.
set -euo pipefail

REGION=${REGION:-ap-south-1}
REMOTE_REGION=${REMOTE_REGION:-ap-southeast-1}
KEY_NAME=${KEY_NAME:?set KEY_NAME to an existing EC2 key pair}
MY_IP=${MY_IP:?set MY_IP to your public IP in CIDR form, e.g. 1.2.3.4/32}
TYPE=${TYPE:-t3.large}
TAG=vault-demo
AMI=$(aws ssm get-parameter --region "$REGION" \
  --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
  --query Parameter.Value --output text)

echo "== VPC + subnet + security group"
VPC=$(aws ec2 create-vpc --region "$REGION" --cidr-block 10.42.0.0/16 --query Vpc.VpcId --output text)
aws ec2 create-tags --region "$REGION" --resources "$VPC" --tags Key=Name,Value=$TAG
aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC" --enable-dns-hostnames
SUBNET=$(aws ec2 create-subnet --region "$REGION" --vpc-id "$VPC" --cidr-block 10.42.1.0/24 \
  --availability-zone "${REGION}a" --query Subnet.SubnetId --output text)
IGW=$(aws ec2 create-internet-gateway --region "$REGION" --query InternetGateway.InternetGatewayId --output text)
aws ec2 attach-internet-gateway --region "$REGION" --vpc-id "$VPC" --internet-gateway-id "$IGW"
RT=$(aws ec2 describe-route-tables --region "$REGION" --filters Name=vpc-id,Values="$VPC" \
  --query 'RouteTables[0].RouteTableId' --output text)
aws ec2 create-route --region "$REGION" --route-table-id "$RT" --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW" >/dev/null
aws ec2 modify-subnet-attribute --region "$REGION" --subnet-id "$SUBNET" --map-public-ip-on-launch
SG=$(aws ec2 create-security-group --region "$REGION" --group-name $TAG --description "vault demo" \
  --vpc-id "$VPC" --query GroupId --output text)
# 9000 (S3) and 9100 (gRPC) only from the group itself; 22/9000/3000 from your IP
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" \
  --ip-permissions "IpProtocol=-1,UserIdGroupPairs=[{GroupId=$SG}]" >/dev/null
for port in 22 9000 3000; do
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG" \
    --protocol tcp --port $port --cidr "$MY_IP" >/dev/null
done

echo "== remote S3 buckets in $REMOTE_REGION"
SUFFIX=$(openssl rand -hex 4)
aws s3 mb "s3://vault-replica-$SUFFIX" --region "$REMOTE_REGION"
aws s3 mb "s3://vault-cold-tier-$SUFFIX" --region "$REMOTE_REGION"

USERDATA_STORAGE=$(cat <<'EOF'
#!/bin/bash
set -e
apt-get update && apt-get install -y docker.io xfsprogs
i=1
for dev in /dev/nvme1n1 /dev/nvme2n1 /dev/nvme3n1 /dev/nvme4n1; do
  while [ ! -b $dev ]; do sleep 2; done
  mkfs.xfs -f $dev && mkdir -p /data/disk$i
  echo "UUID=$(blkid -s UUID -o value $dev) /data/disk$i xfs defaults,noatime 0 2" >> /etc/fstab
  i=$((i+1))
done
mount -a
EOF
)

echo "== 4 storage nodes"
BDM='[{"DeviceName":"/dev/sdf","Ebs":{"VolumeSize":20,"VolumeType":"gp3"}},
      {"DeviceName":"/dev/sdg","Ebs":{"VolumeSize":20,"VolumeType":"gp3"}},
      {"DeviceName":"/dev/sdh","Ebs":{"VolumeSize":20,"VolumeType":"gp3"}},
      {"DeviceName":"/dev/sdi","Ebs":{"VolumeSize":20,"VolumeType":"gp3"}}]'
for n in 1 2 3 4; do
  aws ec2 run-instances --region "$REGION" --image-id "$AMI" --instance-type "$TYPE" \
    --key-name "$KEY_NAME" --subnet-id "$SUBNET" --security-group-ids "$SG" \
    --private-ip-address "10.42.1.1$n" --block-device-mappings "$BDM" \
    --user-data "$USERDATA_STORAGE" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$TAG-node$n},{Key=Project,Value=$TAG}]" \
    --query 'Instances[0].InstanceId' --output text
done

echo "== services node"
aws ec2 run-instances --region "$REGION" --image-id "$AMI" --instance-type t3.large \
  --key-name "$KEY_NAME" --subnet-id "$SUBNET" --security-group-ids "$SG" --private-ip-address 10.42.1.10 \
  --user-data $'#!/bin/bash\napt-get update && apt-get install -y docker.io docker-compose-v2' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$TAG-services},{Key=Project,Value=$TAG}]" \
  --query 'Instances[0].InstanceId' --output text

cat <<EOF

Provisioned. Next (see deploy/aws/README.md):
  1. Copy the repo to each node, build the image:   docker build -f deploy/Dockerfile -t vault .
  2. On node\$N run deploy/aws/run-node.sh node\$N   (uses /etc/hosts entries 10.42.1.11-14 -> node1-4)
  3. On the services node: docker compose -f deploy/aws/services-compose.yml up -d
  4. Replication target: s3://vault-replica-$SUFFIX ($REMOTE_REGION)
     Lifecycle tier:     s3://vault-cold-tier-$SUFFIX ($REMOTE_REGION)
VPC=$VPC SG=$SG SUBNET=$SUBNET
EOF
