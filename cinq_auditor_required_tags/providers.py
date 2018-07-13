import logging

from cloud_inquisitor.plugins.types.accounts import AWSAccount

from cinq_auditor_required_tags.exceptions import ResourceKillError, ResourceStopError
from cloud_inquisitor import get_aws_session
from cloud_inquisitor.constants import NS_AUDITOR_REQUIRED_TAGS
from cloud_inquisitor.log import auditlog
from cloud_inquisitor.plugins.types.resources import EC2Instance

logger = logging.getLogger(__name__)


def process_action(resource, action, resource_type):
    """Process an audit action for a resource, if possible

    Args:
        resource (:obj:`Resource`): A resource object to perform the action on
        action (`str`): Type of action to perform (`kill` or `stop`)
        resource_type (`str`): Type of the resource

    Returns:
        `bool` - Returns the result from the action function
    """
    func_action = action_mapper[resource_type][action]
    if func_action:
        session = get_aws_session(AWSAccount(resource.account))
        client = session.client(
            action_mapper[resource_type]['service_name'],
            region_name=resource.location
        )
        return func_action(client, resource)

    return False


def stop_ec2_instance(client, resource):
    """Stop an EC2 Instance

    This function will attempt to stop a running instance. If the instance is already stopped the function will return
    False, else True.

    Args:
        client (:obj:`boto3.session.Session.client`): A boto3 client object
        resource (:obj:`Resource`): The resource object to stop

    Returns:
        `bool`
    """
    try:
        instance = EC2Instance.get(resource.resource_id)
        if instance.state not in ('stopped', 'terminated'):
            client.stop_instances(InstanceIds=[resource.resource_id])
            logger.debug('Stopped instance {}/{}'.format(resource.account.account_name, resource.resource_id))

            auditlog(
                event='required_tags.ec2.stop',
                actor=NS_AUDITOR_REQUIRED_TAGS,
                data={
                    'resource_id': resource.resource_id,
                    'account_name': resource.account.account_name,
                    'location': resource.location
                }
            )

            return True
        else:
            return False
    except Exception as error:
        logger.info('Failed to stop instance {}/{}: {}'.format(
            resource.account.account_name,
            resource.resource_id,
            error
        ))
        raise ResourceStopError('Failed to stop instance {}/{}: {}'.format(
            resource.account,
            resource.resource_id,
            error
        ))


def terminate_ec2_instance(client, resource):
    """Terminate an EC2 Instance

    This function will terminate an EC2 Instance. Returns `True` if succesful, or raises an exception if not

    Args:
        client (:obj:`boto3.session.Session.client`): A boto3 client object
        resource (:obj:`Resource`): The resource object to terminate

    Returns:
        `bool` - True if the instance was terminated. Will raise an exception if failed
    """
    # TODO: Implement disabling of TerminationProtection
    try:
        client.terminate_instances(InstanceIds=[resource.resource_id])
        logger.info('Terminated instance {}/{}/{}'.format(
            resource.account,
            resource.location,
            resource.resource_id
        ))

        auditlog(
            event='required_tags.ec2.stop',
            actor=NS_AUDITOR_REQUIRED_TAGS,
            data={
                'resource_id': resource.resource_id,
                'account_name': resource.account.account_name,
                'location': resource.location
            }
        )
        return True

    except Exception as error:
        logger.info('Failed to kill instance {}/{}/{}: {}'.format(
            resource.account.account_name,
            resource.location,
            resource.resource_id,
            error
        ))
        raise ResourceKillError('Failed to kill instance {}/{}/{}: {}'.format(
            resource.account.account_name,
            resource.location,
            resource.resource_id,
            error
        ))


action_mapper = {
    'aws_ec2_instance': {
        'service_name': 'ec2',
        'stop': stop_ec2_instance,
        'kill': terminate_ec2_instance
    }
}
