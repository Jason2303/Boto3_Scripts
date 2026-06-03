import argparse, boto3, json
from botocore.exceptions import ClientError
from datetime import datetime, timezone

parser = argparse.ArgumentParser(description='AWS Cloud Security CLI')
subparsers = parser.add_subparsers(dest='command')

# Subcommands
subparsers.add_parser('s3-audit')
subparsers.add_parser('iam-audit')
subparsers.add_parser('guardduty')
subparsers.add_parser('securityhub')

ec2_parser = subparsers.add_parser('ec2')
ec2_parser.add_argument('--tag-key', required=True)
ec2_parser.add_argument('--tag-value', required=True)
ec2_parser.add_argument('--action', required=True, choices=['start', 'stop'])

args = parser.parse_args()

if args.command == 's3-audit':
    s3_client = boto3.client("s3")

    response = s3_client.list_buckets()

    for bucket in response['Buckets']:
        bucket_name = bucket["Name"]

        # Encryption check
        try:
            response_2 = s3_client.get_bucket_encryption(Bucket=bucket_name)
            if response_2['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']:
                print(f"{bucket_name}: Encryption ENABLED")
            else:
                print(f"{bucket_name}: Encryption DISABLED")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                print(f"{bucket_name}: No encryption configured")
            else:
                print(f"{bucket_name}: Encryption check failed — {e}")

        # ACL check
        response_3 = s3_client.get_bucket_acl(Bucket=bucket_name)
        is_public = False
        for grant in response_3['Grants']:
            if grant['Grantee']['Type'] == 'Group' and grant['Grantee'].get('URI') in [
                'http://acs.amazonaws.com/groups/global/AllUsers',
                'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
            ]:
                is_public = True
                break

        if is_public:
            print(f"{bucket_name}: Public ACL DETECTED")
        else:
            print(f"{bucket_name}: ACL is private")

elif args.command == 'iam-audit':
    iam_client = boto3.client("iam")

    for user in iam_client.list_users()['Users']:
        username = user['UserName']

        mfa_devices = iam_client.list_mfa_devices(UserName=username)['MFADevices']
        if not mfa_devices:
            print(f"{username}: No MFA")
        else:
            print(f"{username}: MFA enabled")

        keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in keys:
            age = datetime.now(timezone.utc) - key['CreateDate']
            if age.days > 90:
                print(f"{username}: Key {key['AccessKeyId']} is {age.days} days old")
            else:
                print(f"{username}: Key {key['AccessKeyId']} is {age.days} days old — OK")

elif args.command == 'guardduty':
    guardduty = boto3.client('guardduty', region_name='us-east-1')

    detectors = guardduty.list_detectors()['DetectorIds'][0]
    findings = guardduty.list_findings(
        DetectorId=detectors,
        FindingCriteria={
            'Criterion': {
                'severity': {
                    'Gte': 7
                }
            }
        }
    )

    if not findings['FindingIds']:
        print("No Finding Ids to work with")
    else:
        # 50 Finding Limit
        getfindings = guardduty.get_findings(
            DetectorId=detectors,
            FindingIds=
            findings['FindingIds'],
        )
        with open('findings.json', 'w') as file:
            json.dump(getfindings['Findings'], file, indent=3)

elif args.command == 'ec2':
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    key = f'tag:{args.tag_key}'
    value = args.tag_value

    # Tag Check
    response = ec2_client.describe_instances(
        Filters=[
            {
                'Name': key,
                'Values': [value]
            },
        ]
    )

    if not response['Reservations']:
        print("No matching instance supporting this filtered tag")
    else:
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                if args.action == 'stop':
                    ec2_client.stop_instances(
                        InstanceIds=[instance_id],
                    )
                    print(f"{instance_id} has been stopped")
                elif args.action == 'start':
                    ec2_client.start_instances(
                        InstanceIds=[instance_id]
                    )
                    print(f"{instance_id} has been started")

elif args.command == 'securityhub':
    securityhub_client = boto3.client('securityhub', region_name='us-east-1')
    sns_client = boto3.client('sns', region_name='us-east-1')
    paginator = securityhub_client.get_paginator('get_findings')
    sns_arn = 'arn:aws:sns:us-east-1:355119163695:security-alerts'

    response = paginator.paginate()
    for page in response:
        for dictionary in page['Findings']:
            if dictionary['Severity']['Label'] == "HIGH" or dictionary['Severity']['Label'] == "CRITICAL":
                sns_client.publish(TargetArn=sns_arn, Message=dictionary['Description'])
                print(f"{dictionary['Title']} SNS message has been published")
            else:
                securityhub_client.batch_update_findings(
                    FindingIdentifiers=[
                        {
                            'Id': dictionary['Id'],
                            'ProductArn': dictionary['ProductArn']
                        },
                    ],
                    Workflow={
                        'Status': 'SUPPRESSED'
                    },
                )
                print(f"{dictionary['Title']} has been suppressed due to it being LOW or MEDIUM")

else:
    parser.print_help()
