**************************
cinq-auditor-required-tags
**************************

Please open issues in the `Cloud-Inquisitor <https://github.com/RiotGames/cloud-inquisitor/issues/new?labels=cinq-auditor-required-tags>`_ repository

===========
Description
===========

This auditor reviews, alerts and potentially takes action on AWS objects that are found not to be compliant with the tagging requirements.

=====================
Configuration Options
=====================

+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| Option name         | Default Value                             | Type   | Description                                                                 |
+=====================+===========================================+========+=============================================================================+
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| alert_settings      | See notes below                           | JSON   | Alert and enforcement settings for supported resources                      |
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| always_send_email   | True                                      | bool   | Send emails even in collect mode                                            |
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| audit_ignore_tag    | cinq_ignore                               | string | Cinq will ignore alerting/enforcment if resources are tagged with this      |
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| audit_scope         | aws_ec2_instance                          | string | Select resources (aws_ec2_instance, aws_s3_bucket)                          |
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| collect_only        | True                                      | bool   | Do not shutdown resources, only update caches                               |
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| confirm_shutdown    | True                                      | bool   | Require manual confirmation before shutting down instances                  |
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| email_subject       | Resources missing required tags           | string | Subject of the new issues email notifications                               |
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| enabled             | False                                     | bool   | Enable the Reuiqred Tags auditor                                            |
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| interval            | 30                                        | int    | How often the auditor executes, in minutes                                  |
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| partial_owner_match | False                                     | bool   | Allow partial matches of the Owner tag                                      |
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| permanent_recipient | []                                        | array  | List of email addresses to receive all alerts                               |
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+
| required_tags       | ['owner', 'accounting', 'name']           | array  | List of required tags                                                       |
+---------------------+-------------------------------------------+--------+-----------------------------------------------------------------------------+

Sample alert_settings are specified as follows:

.. code-block:: json

    {
        "aws_s3_bucket": {
         "alert": [
                "0 seconds",
                "30 seconds",
                "60 seconds"
            ],
            "stop": "10 minutes",
            "remove": "20 minutes",
            "scope": ["*"]
        },
        "aws_ec2_instance": {
            "alert": [
                "0 seconds",
                "30 seconds",
                "60 seconds"
            ],
            "stop": "10 minutes",
            "remove": "20 minutes",
            "scope": ["enabled-account-1", "enabled-account-2"]
        }
    }