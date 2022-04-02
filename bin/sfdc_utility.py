#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

"""
This file contains certain ignores for certain linters.

* isort ignores:
- isort: skip = Particular import must be the first import.

* flake8 ignores:
- noqa: F401 -> Def = module imported but unused
    Reason for ignoring = This is necessary as it contains adding a path to sys.path
"""

import import_declare_test  # isort: skip # noqa: F401
import traceback
import urllib.parse

import sfdc_consts
import sfdc_log_helper
from solnlib import conf_manager

logger = sfdc_log_helper.Log().get_logger("splunk_ta_salesforce_utils")


def get_sslconfig(session_key):
    session_key = urllib.parse.unquote(session_key.encode("ascii").decode("ascii"))
    session_key = session_key.encode().decode("utf-8")
    try:
        # Default value of sslconfig will be used if there is any error
        sslconfig = True
        ca_certs_path = ""
        cfm = conf_manager.ConfManager(
            session_key,
            sfdc_consts.APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-{}".format(
                sfdc_consts.APP_NAME, sfdc_consts.SETTINGS_CONF_FILE
            ),
        )
        ca_certs_path = (
            cfm.get_conf(sfdc_consts.SETTINGS_CONF_FILE, refresh=True)
            .get("general")
            .get("ca_certs_path")
            or ""
        ).strip()

    except Exception:
        msg = (
            f"Error while fetching ca_certs_path from '{sfdc_consts.SETTINGS_CONF_FILE}' conf. "
            f"Traceback: {traceback.format_exc()}"
        )
        logger.error(msg)

    if ca_certs_path != "":
        sslconfig = ca_certs_path

    return sslconfig
