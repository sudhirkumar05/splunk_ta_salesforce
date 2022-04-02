#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

"""
This file contains certain ignores for certain linters.

* isort ignores:
- isort: skip = Particular import must be the first import or it is conflicting with the black linter formatting.

* flake8 ignores:
- noqa: F401 -> Def = module imported but unused
    Reason for ignoring = This is necessary as it contains adding a path to sys.path
"""

import import_declare_test  # isort: skip # noqa: F401

import logging

from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

from splunktaucclib.rest_handler.endpoint import (  # isort: skip
    RestModel,
    SingleModel,
    field,
)

from Splunk_TA_salesforce_rh_account_validation import (  # isort: skip
    AccountValidation,
    RemoveRedundantParam,
)

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        "endpoint", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "custom_endpoint", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "username", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "password",
        required=False,
        encrypted=True,
        default=None,
        validator=AccountValidation(),
    ),
    field.RestField(
        "token", required=False, encrypted=True, default=None, validator=None
    ),
    field.RestField(
        "client_id", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "client_secret",
        required=False,
        encrypted=True,
        default=None,
        validator=RemoveRedundantParam(),
    ),
    field.RestField(
        "redirect_url", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "access_token", required=False, encrypted=True, default=None, validator=None
    ),
    field.RestField(
        "refresh_token", required=False, encrypted=True, default=None, validator=None
    ),
    field.RestField(
        "instance_url", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "auth_type", required=True, encrypted=False, default="basic", validator=None
    ),
    field.RestField(
        "sfdc_api_version",
        required=True,
        encrypted=False,
        default="53.0",
        validator=None,
    ),
]
model = RestModel(fields, name=None)


endpoint = SingleModel("splunk_ta_salesforce_account", model, config_name="account")


class SalesforceAccountHandler(AdminExternalHandler):
    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    @staticmethod
    def get_session_key(self):
        return self.getSessionKey()

    def deleteCustomEndpoint(self):
        if self.payload.get("custom_endpoint"):
            del self.payload["custom_endpoint"]

    def handleCreate(self, confInfo):
        self.deleteCustomEndpoint()
        AdminExternalHandler.handleCreate(self, confInfo)

    def handleEdit(self, confInfo):
        self.deleteCustomEndpoint()
        AdminExternalHandler.handleEdit(self, confInfo)


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=SalesforceAccountHandler,
    )
