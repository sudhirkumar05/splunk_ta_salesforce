#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

"""
This module will be used to get oauth token from auth code

This file contains certain ignores for certain linters.

* isort ignores:
- isort: skip = Particular import must be the first import.

* flake8 ignores:
- noqa: F401 -> Def = module imported but unused
    Reason for ignoring = This is necessary as it contains adding a path to sys.path
"""

import import_declare_test  # isort: skip # noqa: F401
import json
from urllib.parse import urlencode

import requests
import splunk.admin as admin
from sfdc_utility import get_sslconfig
from solnlib import conf_manager, log
from solnlib.utils import is_true

log.Logs.set_context()
logger = log.Logs().get_logger("splunk_ta_salesforce_rh_oauth2_token")


class splunk_ta_salesforce_rh_oauth2_token(admin.MConfigHandler):

    """
    This method checks which action is getting called and what parameters are required for the request.
    """

    def setup(self):
        if self.requestedAction == admin.ACTION_EDIT:
            # Add required args in supported args
            for arg in (
                "url",
                "method",
                "grant_type",
                "code",
                "client_id",
                "client_secret",
                "redirect_uri",
            ):
                self.supportedArgs.addReqArg(arg)
        return

    """
    This handler is to get access token from the auth code received
    It takes 'url', 'method', 'grant_type', 'code', 'client_id', 'client_secret', 'redirect_uri' as caller args and
    Returns the confInfo dict object in response.
    """

    def handleEdit(self, confInfo):

        try:
            logger.debug("In OAuth rest handler to get access token")
            # Get args parameters from the request
            url = self.callerArgs.data["url"][0]
            logger.debug("OAuth url %s", url)
            proxy_info = self.getProxyDetails()

            # http = Http(proxy_info=proxy_info)
            method = self.callerArgs.data["method"][0]
            # Create payload from the arguments received
            payload = {
                "grant_type": self.callerArgs.data["grant_type"][0],
                "code": self.callerArgs.data["code"][0],
                "client_id": self.callerArgs.data["client_id"][0],
                "client_secret": self.callerArgs.data["client_secret"][0],
                "redirect_uri": self.callerArgs.data["redirect_uri"][0],
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            # Send http request to get the accesstoken
            sslconfig = get_sslconfig(self.getSessionKey())
            resp = requests.request(
                method,
                url,
                headers=headers,
                proxies=proxy_info,
                timeout=120,
                data=urlencode(payload),
                verify=sslconfig,
            )
            content = resp.content
            content = json.loads(content)
            # Check for any errors in response. If no error then add the content values in confInfo
            if resp.status_code == 200:
                for key, val in content.items():
                    confInfo["token"][key] = val
            else:
                # Else add the error message in the confinfo
                confInfo["token"]["error"] = content["error_description"]
            logger.info(
                "Exiting OAuth rest handler after getting access token with response %s",
                resp.status_code,
            )
        except Exception as exc:
            logger.warning("Error occurred while getting accesstoken using auth code")
            raise exc

    """
    This method is to get proxy details stored in settings conf file
    """

    def getProxyDetails(self):
        # Create confmanger object for the app with realm
        cfm = conf_manager.ConfManager(
            self.getSessionKey(),
            "Splunk_TA_salesforce",
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
            logger.info("Proxy has no credentials found")
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


if __name__ == "__main__":
    admin.init(splunk_ta_salesforce_rh_oauth2_token, admin.CONTEXT_APP_AND_USER)
