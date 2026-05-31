import boto3
from botocore.exceptions import ClientError

s3_client = boto3.client("s3")

response = s3_client.list_buckets()

for bucket in response['Buckets']:
    bucket_name = bucket["Name"]

    # Encryption check
    try:
        response_2 = s3_client.get_bucket_encryption(Bucket=bucket_name)
        if response_2['ServerSideEncryptionConfiguration']['Rules'][0]['BucketKeyEnabled']:
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
        if grant['Grantee']['Type'] == 'Group':
            is_public = True
            break

    if is_public:
        print(f"{bucket_name}: Public ACL DETECTED")
    else:
        print(f"{bucket_name}: ACL is private")




