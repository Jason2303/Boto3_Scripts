import boto3
from datetime import datetime, timezone

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
