import json
from base64 import b64encode
from collections import OrderedDict

from cloud_inquisitor import InquisitorJSONEncoder
from cloud_inquisitor.config import dbconfig
from cloud_inquisitor.constants import ROLE_USER, HTTP, NS_AUDITOR_REQUIRED_TAGS
from cloud_inquisitor.plugins import BaseView
from cloud_inquisitor.plugins.types.issues import RequiredTagsIssue
from cloud_inquisitor.schema import Account
from cloud_inquisitor.utils import MenuItem
from cloud_inquisitor.wrappers import check_auth, rollback
from flask import Response
from pyexcel import save_book_as


class RequiredInstanceTags(BaseView):
    URLS = ['/api/v1/requiredTags']
    MENU_ITEMS = [
        MenuItem(
            'reports',
            'Required Tags',
            'requiredTags.list',
            'requiredTags',
            order=1,
            args={
                'page': 1,
                'count': 100,
                'accounts': None,
                'regions': None,
                'requiredTags': None
            }
        )
    ]

    @rollback
    @check_auth(ROLE_USER)
    def get(self):
        self.reqparse.add_argument('count', type=int, default=100)
        self.reqparse.add_argument('page', type=int, default=None)
        self.reqparse.add_argument('accounts', type=str, default=None, action='append',)
        self.reqparse.add_argument('regions', type=str, default=None, action='append',)
        self.reqparse.add_argument('state', type=str, default=None)
        args = self.reqparse.parse_args()

        required_tags = dbconfig.get('required_tags', NS_AUDITOR_REQUIRED_TAGS, ['owner', 'accounting', 'name']),
        properties = {}

        if args['accounts']:
            properties['account_id'] = [Account.get(x).account_id for x in args['accounts']]

        if args['regions']:
            properties['location'] = args['regions']

        if args['state']:
            properties['state'] = args['state']

        total_issues, instances = RequiredTagsIssue.search(
            limit=args['count'],
            page=args['page'],
            properties=properties
        )

        return self.make_response({
            'issues': instances,
            'requiredTags': required_tags,
            'issueCount': total_issues
        })


# class RequiredInstanceTagsAdmin(BaseView):
#     URLS = ['/api/v1/requiredTagsAdmin']
#
#     @rollback
#     @check_auth(ROLE_NOC)
#     def get(self):
#         self.reqparse.add_argument('count', type=int, default=100)
#         self.reqparse.add_argument('page', type=int, default=None)
#         self.reqparse.add_argument('accounts', type=str, default=None, action='append')
#         self.reqparse.add_argument('regions', type=str, default=None, action='append')
#
#         args = self.reqparse.parse_args()
#         qry = RFC26EnforcementStatus \
#             .query \
#             .outerjoin(EC2Instance, EC2Instance.instance_id == RFC26EnforcementStatus.instance_id) \
#             .filter(RFC26EnforcementStatus.enforcement_state == States.SHUTDOWN_READY)
#
#         # Filter based on account name
#         if args['accounts']:
#             qry = qry.join(Account).filter(Account.account_name.in_(args['accounts']))
#
#         # Filter based on region name
#         if args['regions']:
#             qry = qry.join(Region).filter(Region.region_name.in_(args['regions']))
#
#         total_issues = qry.count()
#         qry = qry.limit(args['count'])
#
#         if args['page'] and (args['page'] - 1) > 0:
#             offset = (args['page'] - 1) * args['count']
#             qry = qry.offset(offset)
#
#         return self.make_response({
#             'instances': [x.to_json() for x in qry.all()],
#             'instanceCount': total_issues
#         })
#
#     @rollback
#     @check_auth(ROLE_NOC)
#     def post(self):
#         self.reqparse.add_argument('instanceIds', type=str, action='append', required=True)
#         args = self.reqparse.parse_args()
#         AuditLog.log('requiredTags.shutdown', session['user'].username, args)
#
#         instances = RFC26EnforcementStatus \
#             .query \
#             .filter(
#                 RFC26EnforcementStatus.instance_id.in_(args['instanceIds']),
#                 RFC26EnforcementStatus.enforcement_state >= States.SHUTDOWN_READY,
#                 EC2Instance.state == 'running'
#             ).all()
#
#         if not instances:
#             return self.make_response({
#                 'message': 'No such instance found ready for shutdown'
#             }, HTTP.BAD_REQUEST)
#
#         instances_shutdown = []
#         instances_failed = []
#         instances_noop = []
#         for instance in instances:
#             try:
#                 sess = get_aws_session(instance.account)
#                 ec2 = sess.resource('ec2', instance.region.region_name)
#
#                 inst = ec2.Instance(instance.instance_id)
#                 if inst.state['Code'] not in (32, 64, 80):
#                     inst.stop()
#
#                     self.log.debug('{}/{} shutdown instance {}/{}'.format(
#                         session['user'].auth_system,
#                         session['user'].username,
#                         instance.account.account_name,
#                         instance.instance_id
#                     ))
#                     instances_shutdown.append(instance.instance_id)
#                 else:
#                     instances_noop.append(instance.instance_id)
#
#                 # Update the instance to reflect that it has now been stopped
#                 instance.enforcement_state = States.SHUTDOWN
#                 instance.last_change = datetime.now()
#                 db.session.add(instance)
#             except Exception as ex:
#                 self.log.exception('Failed shutting down instance: {}'.format(ex))
#                 instances_failed.append(instance.instance_id)
#
#         db.session.commit()
#
#         return self.make_response({
#             'message': 'Instances shutdown',
#             'shutdown': instances_shutdown,
#             'failed': instances_failed,
#             'noAction': instances_noop
#         })


class RequiredInstanceTagsExport(BaseView):
    URLS = ['/api/v1/requiredTagsExport']

    @rollback
    @check_auth(ROLE_USER)
    def get(self):
        self.reqparse.add_argument('requiredTags', type=str, action='append', default=('Name', 'Owner', 'Accounting'))
        self.reqparse.add_argument('accounts', type=str, default=None, action='append')
        self.reqparse.add_argument('regions', type=str, default=None, action='append')
        self.reqparse.add_argument('fileFormat', type=str, default='json', choices=['json', 'xlsx'])
        args = self.reqparse.parse_args()

        properties = {}
        if args['accounts']:
            properties['account_id'] = [Account.get(x).account_id for x in args['accounts']]

        if args['regions']:
            properties['location'] = args['regions']

        total_issues, issues = RequiredTagsIssue.search(
            properties=properties
        )

        if args['fileFormat'] == 'xlsx':
            data = OrderedDict()
            headers = [
                'instanceId', 'accountName', 'regionName', 'lastChange',
                'nextChange', 'shutdownOn', 'missingTags', 'notes', 'tags'
            ]
            for issue in issues:
                instance = issue.instance
                sheet = '{} - {}'.format(instance.account.account_name, issue.location)
                row = [
                    instance.id,
                    instance.account.account_name,
                    issue.location,
                    issue.last_change,
                    issue.next_change,
                    issue.shutdown_on,
                    ';'.join(issue.missing_tags),
                    ';'.join(issue.notes),
                    ';'.join(['{}={}'.format(tag.key, tag.value) for tag in list(instance.tags)])
                ]

                if sheet in data:
                    data[sheet].append(row)
                else:
                    data.update({sheet: [headers, row]})

            response = Response(
                response=b64encode(
                    save_book_as(bookdict=data, dest_file_type='xlsx').read()
                )
            )
        else:
            output = [{
                'instanceId': issue.instance.id,
                'missingTags': issue.missing_tags,
                'notes': issue.notes,
                'regionName': issue.location,
                'accountName': issue.instance.account.account_name,
                'tags': {tag.key: tag.value for tag in issue.instance.tags},
                'lastChange': issue.last_change,
                'nextChange': issue.next_change,
                'shutdownOn': issue.shutdown_on
            } for issue in issues]
            response = Response(
                response=b64encode(
                    bytes(
                        json.dumps(output, indent=4, cls=InquisitorJSONEncoder),
                        'utf-8'
                    )
                )
            )
            response.content_type = 'application/octet-stream'
        response.status_code = HTTP.OK

        return response
