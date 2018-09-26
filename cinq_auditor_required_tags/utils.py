from botocore.exceptions import ClientError


def s3_removal_policy_exists(bucket):
    try:
        return 'cinqDenyObjectUploads' in bucket.Policy().policy
    except ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return False


def s3_removal_lifecycle_policy_exists(bucket):
    try:
        rules = bucket.LifecycleConfiguration().rules
        for rule in rules:
            if rule['ID'] == 'cloudInquisitor':
                return True
        return False
    except ClientError:
        return False
