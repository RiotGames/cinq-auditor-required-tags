import json
import logging
from datetime import datetime

from constants import ActionStatus, S3_REMOVAL_LIFECYCLE_POLICY
from utils import s3_removal_policy_exists, s3_removal_lifecycle_policy_exists

from cloud_inquisitor import get_aws_session
from cloud_inquisitor.constants import AuditActions
from cloud_inquisitor.log import auditlog
from cloud_inquisitor.plugins.types.accounts import AWSAccount
from cloud_inquisitor.plugins.types.enforcements import Enforcement
from cloud_inquisitor.plugins.types.resources import EC2Instance

logger = logging.getLogger(__name__)


def process_action(resource, action, resource_type, action_issuer='unknown'):
    """Process an audit action for a resource, if possible

    Args:
        resource (:obj:`Resource`): A resource object to perform the action on
        action (`str`): Type of action to perform (`kill` or `stop`)
        resource_type (`str`): Type of the resource
        action_issuer (`str`): The issuer of the action
    Returns:
        `ActionStatus`
    """
    func_action = action_mapper[resource_type][action]
    if func_action:
        client = get_aws_session(AWSAccount(resource.account)).client(
            action_mapper[resource_type]['service_name'],
            region_name=resource.location
        )
        try:
            action_status, metrics = func_action(client, resource)
            Enforcement.create(resource.account_id, resource.resource_id, action, datetime.now(), metrics)
        except Exception as ex:
            action_status = ActionStatus.FAILED
            logger.error('Failed to apply action {} to {}: {}'.format(action, resource.resource_id, ex))
        finally:
            auditlog(
                event='{}.{}.{}.{}'.format(action_issuer, resource_type, action, action_status),
                actor=action_issuer,
                data={
                    'resource_id': resource.resource_id,
                    'account_name': resource.account.account_name,
                    'location': resource.location
                }
            )
            return action_status
    else:
        logger.error('Failed to apply action {} to {}: Not supported'.format(action, resource.resource_id))
        return ActionStatus.FAILED


def stop_ec2_instance(client, resource):
    """Stop an EC2 Instance

    This function will attempt to stop a running instance. If the instance is already stopped the function will return
    False, else True.

    Args:
        client (:obj:`boto3.session.Session.client`): A boto3 client object
        resource (:obj:`Resource`): The resource object to stop

    Returns:
        `ActionStatus`
    """
    instance = EC2Instance.get(resource.resource_id)
    if instance.state in ('stopped', 'terminated'):
        return ActionStatus.IGNORED, {}

    client.stop_instances(InstanceIds=[resource.resource_id])
    return ActionStatus.SUCCEED, {'instance_type': resource.instance_type, 'public_ip': resource.public_ip}


def terminate_ec2_instance(client, resource):
    """Terminate an EC2 Instance

    This function will terminate an EC2 Instance. Returns `True` if succesful, or raises an exception if not

    Args:
        client (:obj:`boto3.session.Session.client`): A boto3 client object
        resource (:obj:`Resource`): The resource object to terminate

    Returns:
        `ActionStatus`
    """
    # TODO: Implement disabling of TerminationProtection
    instance = EC2Instance.get(resource.resource_id)
    if instance.state == 'terminated':
        return ActionStatus.IGNORED, {}
    client.terminate_instances(InstanceIds=[resource.resource_id])
    return ActionStatus.SUCCEED, {'instance_type': resource.instance_type, 'public_ip': resource.public_ip}


def delete_s3_bucket(client, resource):
    for prop in resource.properties:
        if prop.name == 'metrics':
            metrics = prop.value
    else:
        metrics = {}

    bucket_policy = {
        'Version': '2012-10-17',
        'Id': 'PutObjPolicy',
        'Statement': [
            {
                'Sid': 'cinqDenyObjectUploads',
                'Effect': 'Deny',
                'Principal': '*',
                'Action': ['s3:PutObject', 's3:GetObject'],
                'Resource': 'arn:aws:s3:::{}/*'.format(resource.resource_id)
            }
        ]
    }

    has_objects = client.list_objects_v2(Bucket=resource.resource_id, MaxKeys=1).get('Contents', None)
    has_versions = client.list_object_versions(Bucket=resource.resource_id, MaxKeys=1).get('Versions', None)
    if not has_objects and not has_versions:
        client.delete_bucket(Bucket=resource.resource_id)
        return ActionStatus.SUCCEED, metrics

    policy_exists = s3_removal_policy_exists(client, resource)
    lifecycle_policy_exists = s3_removal_lifecycle_policy_exists(client, resource)
    if policy_exists and lifecycle_policy_exists:
        return ActionStatus.IGNORED, {}

    if not policy_exists:
        client.put_bucket_policy(Bucket=resource.resource_id, Policy=json.dumps(bucket_policy))
        logger.info('Added policy to prevent putObject in s3 bucket {} in {}'.format(
            resource.resource_id,
            resource.account
        ))

    if not lifecycle_policy_exists:
        # Grab S3 Metrics before lifecycle policies start removing objects

        client.put_bucket_lifecycle_configuration(
            Bucket=resource.resource_id,
            LifecycleConfiguration=S3_REMOVAL_LIFECYCLE_POLICY
        )
        logger.info('Added policy to delete bucket contents in s3 bucket {} in {}'.format(
            resource.resource_id,
            resource.account
        ))

    return ActionStatus.SUCCEED, metrics


def delete_ebs_volume(client, resource):
    client.delete_volume(VolumeId=resource.resource_id)
    return ActionStatus.SUCCEED, {}


action_mapper = {
    'aws_ec2_instance': {
        'service_name': 'ec2',
        AuditActions.STOP: stop_ec2_instance,
        AuditActions.REMOVE: terminate_ec2_instance
    },
    'aws_s3_bucket': {
        'service_name': 's3',
        AuditActions.STOP: None,
        AuditActions.REMOVE: delete_s3_bucket
    },
    'aws_ebs_volume': {
        'service_name': 'ec2',
        AuditActions.STOP: None,
        AuditActions.REMOVE: delete_ebs_volume
    }
}
