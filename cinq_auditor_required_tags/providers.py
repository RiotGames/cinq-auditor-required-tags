import logging
from cloud_inquisitor import get_aws_session
from cinq_auditor_required_tags.exceptions import ResourceKillError, ResourceStopError


logger = logging.getLogger(__name__)


def process_action(resource, action, resource_type):
    func_action = action_mapper[resource_type][action]
    if func_action:
        session = get_aws_session(resource.account)
        client = session.client(
            action_mapper[resource_type]['service_name'],
            region_name=resource.location
        )
        return func_action(client, resource)


def stop_ec2_instance(client, resource):
    try:
        client.stop_instances(InstanceIds=['{}'.format(resource.resource_id)])
        logger.info('Stopped instance {} in {}'.format(resource.resource_id, resource.account))
    except Exception as error:
        logger.info('Failed to stop instance {} in {}'.format(resource.resource_id, resource.account))
        raise ResourceStopError(
            'Failed to stop instance {} in {}. Reason: {}'.format(resource.resource_id, resource.account, error)
        )


def terminate_ec2_instance(client, resource):
    try:
        client.terminate_instances(InstanceIds=['{}'.format(resource.resource_id)])
        logger.info('Terminated instance {} in {}'.format(resource.resource_id, resource.account))
    except Exception as error:
        logger.info('Failed to kill instance {} in {}'.format(resource.resource_id, resource.account))
        raise ResourceKillError(
            'Failed to kill instance {} in {}. Reason: {}'.format(resource.resource_id, resource.account, error)
        )


action_mapper = {
    'aws_ec2_instance': {
        'service_name': 'ec2',
        'stop': stop_ec2_instance,
        'kill': terminate_ec2_instance
    }
}
