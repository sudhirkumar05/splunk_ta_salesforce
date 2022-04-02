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
import copy
import traceback

import requests
import splunk.admin as admin
from cloudconnectlib.core.ext import regex_search
from sfdc_utility import get_sslconfig
from solnlib import conf_manager, log
from solnlib.utils import is_true
from splunktaucclib.rest_handler.endpoint.validator import Validator

APP_NAME = "Splunk_TA_salesforce"
_FAULT_STRING_REGEX = "\\<faultstring\\>(?P<faultstring>.*)\\<\\/faultstring\\>"
_FAULT_CODE_REGEX = "\\<faultcode\\>sf:(?P<faultcode>.*)\\<\\/faultcode\\>"
_DEFAULT_ERROR = (
    "Login Salesforce failed. Please check your network environment and credentials."
)

log.Logs.set_context()
logger = log.Logs().get_logger("ta_salesforce_basic_account_validation")


class GetSessionKey(admin.MConfigHandler):
    def __init__(self):
        self.session_key = self.getSessionKey()


class AccountValidation(Validator):
    def __init__(self, *args, **kwargs):
        super(AccountValidation, self).__init__(*args, **kwargs)

    def getProxyDetails(self):
        session_key_obj = GetSessionKey()
        session_key = session_key_obj.session_key
        # Create confmanger object for the app with realm
        cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm="__REST_CREDENTIAL__#Splunk_TA_salesforce#configs/conf-splunk_ta_salesforce_settings",
        )
        # Get Conf object of apps settings
        conf = cfm.get_conf("splunk_ta_salesforce_settings")
        # Get proxy stanza from the settings
        proxy_config = conf.get("proxy", True)
        if not proxy_config or not is_true(proxy_config.get("proxy_enabled")):
            logger.info("Proxy is not enabled")
            return None

        url = proxy_config.get("proxy_url")
        port = proxy_config.get("proxy_port")

        if url or port:
            if not url:
                raise ValueError('Proxy "url" must not be empty')
            if not self.is_valid_port(port):
                raise ValueError('Proxy "port" must be in range [1,65535]: %s' % port)

        user = proxy_config.get("proxy_username")
        password = proxy_config.get("proxy_password")

        if not all((user, password)):
            logger.info("No proxy credentials found")
            user, password = None, None

        proxy_type = proxy_config.get("proxy_type")
        proxy_type = proxy_type.lower() if proxy_type else "http"

        rdns = is_true(proxy_config.get("proxy_rdns"))

        # socks5 causes the DNS resolution to happen on the client
        # socks5h causes the DNS resolution to happen on the proxy server
        if rdns and proxy_type == "socks5":
            proxy_type = "socks5h"

        if user and password:
            proxy_info = {"http": f"{proxy_type}://{user}:{password}@{url}:{int(port)}"}
        else:
            proxy_info = {"http": f"{proxy_type}://{url}:{int(port)}"}

        proxy_info["https"] = proxy_info["http"]

        return proxy_info

    """
    Method to check if the given port is valid or not
    :param port: port number to be validated
    :type port: ``int``
    """

    def is_valid_port(self, port):
        try:
            return 0 < int(port) <= 65535
        except ValueError:
            return False

    def validate(self, value, data):

        data = empty_values(data)
        if not data:
            return False
        if data.get("auth_type", "") == "oauth":
            # exiting for oauth auth_type as its account validation is already done in JS.
            return True
        # Validate Salesforce Account credentials
        logger.info("Validating salesforce account credentials")

        # Get Proxy configurations from splunk_ta_salesforce_settings.conf
        proxy_info = self.getProxyDetails()

        defaults = copy.deepcopy(data)
        rq_body = (
            '<?xml version="1.0" encoding="utf-8" ?>'
            '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            ' xmlns:env="http://schemas.xmlsoap.org/soap/envelope/">'
            "<env:Body>"
            '<n1:login xmlns:n1="urn:partner.soap.sforce.com">'
            "<n1:username>" + defaults["username"] + "</n1:username>"
            "<n1:password><![CDATA["
            + defaults["password"]
            + "]]>"
            + defaults.get("token", "")
            + "</n1:password>"
            "</n1:login></env:Body>"
            "</env:Envelope>"
        )

        header = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": "login"}

        try:
            account_endpoint = defaults["endpoint"]
            account_sfdc_api_version = defaults["sfdc_api_version"]
            logger.info(
                "Invoking request to [https://"
                + account_endpoint
                + "/services/Soap/u/"
                + account_sfdc_api_version
                + "/] using [POST] method"
            )
            sslconfig = get_sslconfig(GetSessionKey().session_key)
            resp = requests.request(
                method="POST",
                url="https://"
                + account_endpoint
                + "/services/Soap/u/"
                + account_sfdc_api_version
                + "/",
                proxies=proxy_info,
                headers=header,
                timeout=120,
                data=rq_body,
                verify=sslconfig,
            )
            content = resp.content.decode()
        except Exception:
            msg = (
                f"Some error occured while validating credentials for salesforce username {defaults['username']}. "
                "Check ta_salesforce_basic_account_validation.log for more details."
            )
            logger.error(  # nosemgrep  False Positive: Not exposing any secret credential
                f"While validating credentials for salesforce username {defaults['username']}, some error occured. "
                f"Check your network connection and try again.\nreason={traceback.format_exc()}"
            )
            self.put_msg(msg, True)
            return False

        if int(resp.status_code) == 200:
            logger.info(  # nosemgrep  False Positive: Not exposing any secret credential
                "Successfully validated salesforce account credentials for username %s",
                defaults["username"],
            )
            return True
        else:
            error = regex_search(_FAULT_CODE_REGEX, content) if content else {}
            fault_code = error.get("faultcode", _DEFAULT_ERROR)
            error_description = (
                regex_search(_FAULT_STRING_REGEX, content) if content else {}
            )
            fault_string = error_description.get("faultstring", _DEFAULT_ERROR)

            code_msg_tbl = {
                "INVALID_LOGIN": "Invalid username, password, security token; or user locked out.",
                "LOGIN_MUST_USE_SECURITY_TOKEN": (
                    "When accessing Salesforce, either via a desktop client "
                    "or the API from outside of your company's trusted networks, you must add a security token "
                    "to your password to log in."
                ),
                "REQUEST_LIMIT_EXCEEDED": "Login Failed, TotalRequests Limit exceeded.",
            }

            fault_msg = code_msg_tbl.get(fault_code, _DEFAULT_ERROR)
            msg = fault_msg
            logger.error(
                "Login failed for salesforce account %s with reason %s",
                defaults["username"],
                fault_string,
            )
            self.put_msg(msg, True)
            return False


class ProxyValidation(Validator):
    """
    Validate Proxy details provided
    """

    def __init__(self, *args, **kwargs):
        super(ProxyValidation, self).__init__(*args, **kwargs)

    def validate(self, value, data):
        logger.info("Validating proxy details")

        username_val = data.get("proxy_username")
        password_val = data.get("proxy_password")

        # If password is specified, then username is required
        if password_val and not username_val:
            self.put_msg(
                "Username is required if password is specified", high_priority=True
            )
            return False
        # If username is specified, then password is required
        elif username_val and not password_val:
            self.put_msg(
                "Password is required if username is specified", high_priority=True
            )
            return False

        # If length of username is not satisfying the String length criteria
        if username_val:
            str_len = len(username_val)
            _min_len = 1
            _max_len = 50
            if str_len < _min_len or str_len > _max_len:
                msg = (
                    "String length of username should be between %(min_len)s and %(max_len)s"
                    % {"min_len": _min_len, "max_len": _max_len}
                )
                self.put_msg(msg, high_priority=True)
                return False

        if password_val:
            str_len = len(password_val)
            _min_len = 1
            _max_len = 8192
            if str_len < _min_len or str_len > _max_len:
                msg = (
                    "String length of password should be between %(min_len)s and %(max_len)s"
                    % {"min_len": _min_len, "max_len": _max_len}
                )
                self.put_msg(msg, high_priority=True)
                return False

        return True


class RemoveRedundantParam(Validator):
    """
    Validates and removes redundant parameter based on account type selected
    """

    def __init__(self, *args, **kwargs):
        super(RemoveRedundantParam, self).__init__(*args, **kwargs)

    def validate(self, value, data):
        data = empty_values(data)
        return False if not data else True


def empty_values(data_dict):
    """
    Empties the values of keys irrelevant to auth_type selected. Logs an error
    of auth_type provided is invalid.
    """
    if data_dict.get("auth_type", "") == "basic":
        data_dict["client_id"] = data_dict["client_secret"] = data_dict[
            "redirect_url"
        ] = data_dict["instance_url"] = data_dict["refresh_token"] = data_dict[
            "access_token"
        ] = ""
    elif data_dict.get("auth_type", "") == "oauth":
        data_dict["password"] = data_dict["username"] = data_dict["token"] = ""
    else:
        logger.error(
            "Received an invalid Authentication Type: {}. "
            "Please reconfigure the account.".format(
                data_dict.get("auth_type", "<no authentication type found>")
            )
        )
        return False

    return data_dict
