from cloud_inquisitor.config import dbconfig
from cloud_inquisitor.constants import NS_AUDITOR_REQUIRED_TAGS


class ActionStatus:
    SUCCEED = 'succeed'
    FAILED = 'failed'
    IGNORED = 'ignored'


S3_REMOVAL_LIFECYCLE_POLICY = {
    'Rules': [
        {'Status': 'Enabled',
         'NoncurrentVersionExpiration': {u'NoncurrentDays': 1},
         'Filter': {u'Prefix': ''},
         'Expiration': {
             u'Days': dbconfig.get('lifecycle_expiration_days', NS_AUDITOR_REQUIRED_TAGS, 3)
         },
         'AbortIncompleteMultipartUpload': {u'DaysAfterInitiation': 3},
         'ID': 'cloudInquisitor'}
    ]
}
