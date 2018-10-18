from cloud_inquisitor.config import dbconfig
from cloud_inquisitor.constants import NS_AUDITOR_REQUIRED_TAGS


class ActionStatus:
    SUCCEED = 'succeed'
    FAILED = 'failed'
    IGNORED = 'ignored'
