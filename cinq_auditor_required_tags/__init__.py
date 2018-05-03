from datetime import datetime, timedelta

from cloud_inquisitor import get_aws_session
from cloud_inquisitor.config import dbconfig, ConfigOption
from cloud_inquisitor.constants import NS_AUDITOR_REQUIRED_TAGS, NS_GOOGLE_ANALYTICS
from cloud_inquisitor.database import db
from cloud_inquisitor.plugins import BaseAuditor
from cloud_inquisitor.plugins.types.issues import RequiredTagsIssue
from cloud_inquisitor.plugins.types.resources import EC2Instance
from cloud_inquisitor.schema import AuditLog, Account
from cloud_inquisitor.utils import (
    validate_email,
    get_template,
    merge_lists,
    get_resource_id,
    send_notification,
    NotificationContact
)

INTERVALS = (
    None,                   # 0, Compliant, no alert
    None,                   # 1, Detected, alert
    timedelta(weeks=3),     # 2, Alert after 3 weeks
    timedelta(days=6),      # 3, Alert again after another 1 week
    timedelta(days=1),      # 4, Prepare shutdown after 3rd warning
    timedelta(minutes=5),   # 5, Shutdown instance (can be either manual or automated)
    timedelta(weeks=12)     # 6, Delete after 12 weeks from shutdown
)


class States(object):
    COMPLIANT = 0
    DETECTED = 1
    ALERT_3WEEKS = 2
    ALERT_4WEEKS = 3
    SHUTDOWN_READY = 4
    SHUTDOWN = 5
    TERMINATE = 6


class RequiredTagsAuditor(BaseAuditor):
    name = 'Required Tags Compliance'
    ns = NS_AUDITOR_REQUIRED_TAGS
    interval = dbconfig.get('interval', ns, 30)
    tracking_enabled = dbconfig.get('enabled', NS_GOOGLE_ANALYTICS, False)
    tracking_id = dbconfig.get('tracking_id', NS_GOOGLE_ANALYTICS)
    confirm_shutdown = dbconfig.get('confirm_shutdown', ns, True)
    required_tags = []
    collect_only = None
    start_delay = 0
    options = (
        ConfigOption('enabled', False, 'bool', 'Enable the Required Tags auditor'),
        ConfigOption('interval', 30, 'int', 'How often the auditor executes, in minutes.'),
        ConfigOption('required_tags', ['owner', 'accounting', 'name'], 'array', 'List of required tags'),
        ConfigOption('collect_only', True, 'bool', 'Do not shutdown instances, only update caches'),
        ConfigOption('permanent_recipient', [], 'array', 'List of email addresses to receive all alerts'),
        ConfigOption('always_send_email', True, 'bool', 'Send emails even in collect mode'),
        ConfigOption('email_subject', 'EC2 Instances missing required tags', 'string',
                     'Subject of the new issues email notifications'),
        ConfigOption('email_subject_fixed', 'Fixed EC2 Instances missing required tags', 'string',
                     'Subject of the fixed issues email notification'),
        ConfigOption('partial_owner_match', True, 'bool', 'Allow partial matches of the Owner tag'),
        ConfigOption('confirm_shutdown', True, 'bool', 'Require manual confirmation before shutting down instances')
    )

    def __init__(self):
        super().__init__()
        self.log.debug('Starting RequiredTags auditor')

        self.required_tags = self.dbconfig.get('required_tags', self.ns, ['owner', 'accounting', 'name'])
        self.collect_only = self.dbconfig.get('collect_only', self.ns, True)
        self.always_send_email = self.dbconfig.get('always_send_email', self.ns, False)
        self.permanent_email = [NotificationContact('email', email) for email in self.dbconfig.get('permanent_recipient', self.ns, [])]
        self.subject_issues = self.dbconfig.get('email_subject', self.ns, 'EC2 Instances missing required tags')
        self.subject_fixed = self.dbconfig.get('email_subject_fixed', self.ns, 'Fixed EC2 Instances missing required tags')
        self.grace_period = self.dbconfig.get('grace_period', self.ns, 4)
        self.partial_owner_match = self.dbconfig.get('partial_owner_match', self.ns, True)

    def run(self, *args, **kwargs):
        """Execute the auditor"""
        instances = self.update_cache()
        self.shutdown_instances()
        self.terminate_instances()

        notices = {}
        for acct in instances:
            issues = instances[acct].get('issues', [])
            fixed = instances[acct].get('fixed', [])
            recipients = acct.get_contacts()

            if self.permanent_email:
                if type(self.permanent_email) in (list, tuple):
                    recipients += self.permanent_email
                else:
                    recipients.append(self.permanent_email)

            if True or not self.collect_only or self.always_send_email:
                for issue in issues:
                    for recipient in merge_lists(recipients, issue.instance.get_owner_emails()):
                        notices.setdefault(recipient.value, {'issues': [], 'fixed': [], 'contact': [recipient]})['issues'].append(issue)

                for issue in fixed:
                    for recipient in merge_lists(recipients, issue.instance.get_owner_emails()):
                        notices.setdefault(recipient.value, {'issues': [], 'fixed': [], 'contact': [recipient]})['fixed'].append(issue)

        self.notify(notices)

    def notify(self, notices):
        """Send notifications to the recipients provided

        Args:
            notices (:obj:`dict` of `str`: `list`): A dictionary mapping notification messages to the recipient.

        Returns:
            `None`
        """
        html_template_issue = get_template('required_tags_alert.html')
        html_template_fixed = get_template('required_tags_fixed.html')

        text_template_issue = get_template('required_tags_alert.txt')
        text_template_fixed = get_template('required_tags_fixed.txt')
        for recipient, data in list(notices.items()):
            if len(data['issues']) > 0:
                body_html = html_template_issue.render(resources=data['issues'])
                body_text = text_template_issue.render(resources=data['issues'])
                send_notification(
                    subsystem='Required Tags Compliance',
                    recipients=data['contact'],
                    subject=self.subject_issues.format(data),
                    body_html=body_html,
                    body_text=body_text
                )

            if len(data['fixed']) > 0:
                body_html = html_template_fixed.render(resources=data['fixed'])
                body_text = text_template_fixed.render(resources=data['fixed'])
                send_notification(
                    subsystem='Required Tags Compliance',
                    recipients=data['contact'],
                    subject=self.subject_fixed.format(data),
                    body_html=body_html,
                    body_text=body_text
                )

    def shutdown_instances(self):
        """Shutdown instances that have been non-compliant for the configured amount of time. Returns a list of IDs of
        the instances that were shutdown

        Returns:
            :obj:`dict` of :obj:`Account`: :obj:`list` of `str`
        """
        total, issues = RequiredTagsIssue.search(properties={'state': States.SHUTDOWN})
        shutdown_instances = {}
        for issue in issues:
            try:
                session = get_aws_session(issue.instance.account)
                ec2 = session.resource('ec2', region_name=issue.instance.location)

                instance = ec2.Instance(issue.instance.id)
                if instance.state not in (32, 64, 80):
                    shutdown_instances.setdefault(issue.instance.account, []).append(issue.instance.id)

                    instance.stop()
                    self.log.debug('Shutdown instance {}/{}'.format(
                        issue.instance.account.account_name,
                        issue.instance_id
                    ))

            except Exception:
                self.log.exception(
                    'Failed to shutdown instance {0}/{1}'.format(
                        issue.instance.account.account_name,
                        issue.instance.id
                    )
                )

        if shutdown_instances:
            AuditLog.log(
                event='requiredTags.shutdown_instances',
                actor=self.ns,
                data={
                    'instances': shutdown_instances
                }
            )

        return shutdown_instances

    def terminate_instances(self):
        """Terminate instances that have been non-compliant for the configured amount of time. Returns a list of IDs of
        the instances that were terminated

        Returns:
            :obj:`dict` of :obj:`Account`: :obj:`list` of `str`
        """
        total, issues = RequiredTagsIssue.search(properties={'state': States.TERMINATE})
        terminated_instances = {}
        for issue in issues:
            try:
                session = get_aws_session(issue.instance.account)
                ec2 = session.resource('ec2', region_name=issue.region.region_name)

                instance = ec2.Instance(issue.instance.id)
                if instance.state not in (32, 64, 80):
                    instance.terminate()

                    terminated_instances.setdefault(issue.instance.account, []).append(issue.instance.id)
                    self.log.debug('Terminated instance {}/{}'.format(
                        issue.instance.account.account_name,
                        issue.instance_id
                    ))

            except Exception:
                self.log.exception(
                    'Failed to terminate instance {0}/{1}'.format(
                        issue.instance.account.account_name,
                        issue.instance.id
                    )
                )

        if terminated_instances:
            AuditLog.log(
                event='requiredTags.terminate_instances',
                actor=self.ns,
                data={
                    'instances': terminated_instances
                }
            )

        return terminated_instances

    def update_cache(self):
        """Update the database with the current status to enable update only mode. Returns a dict of issues (new,
        updated and fixed) to alert for

        Returns:
            :obj:`dict` of `str`: `dict`
        """
        instances = {}

        # region Detect missing tags on all existing instances
        try:
            for instance_id, instance in EC2Instance.get_all().items():
                if self.grace_period > 0 and instance.launch_date > datetime.now() - timedelta(hours=self.grace_period):
                    continue

                missing_tags = []
                notes = []
                itags = {tag.key.lower(): tag.value for tag in instance.tags}

                for key in [x.lower() for x in self.required_tags]:
                    if key not in itags:
                        missing_tags.append(key)

                    elif key == 'owner' and not validate_email(itags[key], self.partial_owner_match):
                        missing_tags.append(key)
                        notes.append('Owner tag is not a valid email address')

                if len(missing_tags) > 0:
                    instances[get_resource_id('reqtag', instance.id)] = {
                        'instance': instance,
                        'missing_tags': missing_tags,
                        'notes': notes,
                        'account': Account.get_by_id(instance.account_id)
                    }
        finally:
            db.session.rollback()
        # endregion

        existing_issues = RequiredTagsIssue.get_all()
        new_issues = {}
        fixed_issues = {}

        # region New and existing issues
        try:
            for issue_id, data in list(instances.items()):
                instance = data['instance']
                account = Account.get_by_id(instance.account_id)
                now = datetime.now()

                # Create new issues
                if issue_id not in existing_issues:
                    properties = {
                        'instance_id': instance.id,
                        'account_id': instance.account_id,
                        'location': instance.location,
                        'state': States.DETECTED,
                        'last_change': now,
                        'missing_tags': sorted(data['missing_tags']),
                        'notes': sorted(data['notes']),
                        'next_change': now + INTERVALS[States.ALERT_3WEEKS],
                        'shutdown_on': now + sum(INTERVALS[2:-1], timedelta())
                    }
                    issue = RequiredTagsIssue.create(issue_id, properties=properties)
                    new_issues.setdefault(account, []).append(issue)
                    db.session.add(issue.issue)

                # Check for updates on existing issues
                else:
                    issue = existing_issues[issue_id]

                    # Don't do anything else if we are in pure collect mode, or if it has already been terminated
                    if self.collect_only or issue.state >= States.TERMINATE or (
                                    issue.state == States.SHUTDOWN_READY and self.confirm_shutdown
                    ):
                        self.log.debug('Skipping state change for {}/{}: {}. Collect Only: {}, Confirm: {}'.format(
                            issue.instance.account.account_name,
                            issue.instance_id,
                            issue.state,
                            self.collect_only,
                            self.confirm_shutdown
                        ))
                        continue

                    next_state = issue.state + 1
                    next_change = issue.last_change + INTERVALS[next_state]
                    data = {
                        'state': issue.state if now < next_change else next_state,
                        'missing_tags': sorted(data['missing_tags']),
                        'notes': sorted(data['notes']),
                        'next_change': next_change,
                    }

                    if issue.update(data):
                        db.session.add(issue.issue)
                        new_issues.setdefault(account, []).append(issue)

            db.session.commit()
        finally:
            db.session.rollback()
        # endregion

        # region Fixed instances
        try:
            for issue_id, issue in list(existing_issues.items()):
                if issue_id not in instances:
                    account = Account.get_by_id(issue.account_id)

                    fixed_issues.setdefault(account, []).append(issue)
                    db.session.delete(issue.issue)
            db.session.commit()
        finally:
            db.session.rollback()
        # endregion

        output = {}
        for acct, data in list(new_issues.items()):
            output.setdefault(acct, {'issues': [], 'fixed': []})['issues'] += data

        for acct, data in list(fixed_issues.items()):
            output.setdefault(acct, {'issues': [], 'fixed': []})['fixed'] += data

        return output
