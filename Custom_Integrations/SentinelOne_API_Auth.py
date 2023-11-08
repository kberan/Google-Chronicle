from exceptions import (
    SentinelOneV2UnauthorizedError,
    SentinelOneV2HTTPError,
    SentinelOneV2ConnectivityError,
    SentinelOneV2PermissionError,
    SentinelOneV2NotFoundError,
    SentinelOneV2AlreadyExistsError,
    SentinelOneV2BadRequestError,
    SentinelOneV2TooManyRequestsError,
)
from utils import filter_items
import requests


# Payloads.
LOGIN_PAYLOAD = {
    "username": "",
    "rememberMe": "true",
    "password": ""
}

# Headers.
HEADERS = {
    "Content-Type": "application/json"
}


class SentinelOneV2Manager(object):
    def __init__(self, api_root, api_token, api_version, verify_ssl=False, force_check_connectivity=False, logger=None):
        """
        
        :param api_root: API root URL.
        :param api_token: SentinelOne api token
        :param verify_ssl: Enable (True) or disable (False). If enabled, verify the SSL certificate for the connection.
        :param force_check_connectivity: True or False. If True it will check connectivity initially.
        :param logger: Siemplify logger.
        """
        self.api_root = api_root
        self.session = requests.session()
        self.session.verify = verify_ssl
        self.session.headers = copy.deepcopy(HEADERS)
        self.session.headers['Authorization'] = "ApiToken {}".format(api_token)
        self.parser = SentinelOneV2Parser()
        self.logger = logger
        self.api_version = api_version
        self.api_endpoints = API_ENDPOINTS

        if force_check_connectivity:
            self.test_connectivity()

    def _get_full_url(self, url_id, with_api_version=True, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param api_version: {str or float}
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urllib.parse.urljoin(
            self.api_root, self.api_endpoints[url_id].format(api_version=self.api_version, **kwargs) if
            with_api_version else self.api_endpoints[url_id].format(**kwargs)
        )

    def test_connectivity(self):
        """
        Test connectivity to SentinelOne V2
        :return: {bool} True if successful, exception otherwise
        """
        try:
            response = self.session.get(self._get_full_url('ping'))
            self.validate_response(response)
            return True
        except Exception as e:
            raise SentinelOneV2ConnectivityError('Unable to connect to SentinelOne V2. Error: {}'.format(e))
