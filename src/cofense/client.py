"""
Copyright 2013-2023 Cofense, Inc.  All rights reserved.

This software is provided by Cofense, Inc. ("Cofense") on an "as is" basis and any express or implied warranties,
including but not limited to the implied warranties of merchantability and fitness for a particular purpose, are
disclaimed in all aspects.  In no event will Cofense be liable for any direct, indirect, special, incidental or
consequential damages relating to the use of this software, even if advised of the possibility of such damage. Use of
this software is pursuant to, and permitted only in accordance with, the agreement between you and Cofense.

Cofense Base Module (for both Python 2.x & Python 3.x)
Author: Josh Larkins/Kevin Stilwell/Robert McMahon/Marcus Vogt
Support: support@cofense.com
ChangesetID: CHANGESETID_VERSION_STRING

"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, Iterator, List

import re
import pydantic
import requests
import urllib3.exceptions
from pydantic import BaseModel
from requests import Response



__all__ = [
    "CofenseClient",
    "CofenseThreat",
]

log = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CofenseClient:

    def __init__(self, url: str, proxy_url: str, proxy_user: str, proxy_pass:str, api_user: str, api_pass: str, ssl_verify: bool = True):       
        """
        Constructor.
        :param url: Cofense ThreatHQ url  (usually https://www.threathq.com/apiv1/)
        :param proxy_url: HTTP(S) proxy 
        :param proxy_user: HTTP(S) proxy username
        :param proxy_password: HTTP(S) proxy password
        :param api_user:  Cofense ThreatHQ API username
        :param api_pass: Cofense ThreatHQ API password
        :param ssl_verify: Verify SSL connections
        """    

        if not url:
            raise ValueError("Cofense ThreatHQ URL must be set")

        self._api_url = url
        
        if proxy_url:
            if proxy_user and proxy_pass:
                proxy = re.sub('^https?:\/\/','', proxy_url)
                proxy = "https://{}:{}@{}".format(proxy_user, proxy_pass, proxy)
                self._proxy_url = { 'https' : proxy } # need to stick in array  TODO
            else:
                self._proxy_url = { 'https' : proxy_url } # only support https proxy
        self._verify = ssl_verify

        if not api_user or not api_pass:
            raise ValueError("Cofense ThreatHQ API id and key must be set")

        self._api_url = url
        self._session = requests.Session()
        if self._proxy_url:
            self._session.proxies.update(proxy_url)
        self._session.auth = (api_user, api_pass)
        self._session.verify = ssl_verify


    def query(self) -> Iterator[CofenseThreat]:
        """
        Process the feed URL and return any indicators.
        :return: Feed results
        """
        resp: Response = self._session.get(self._api_url)
        resp.raise_for_status()

        result_type = Dict[
            str,  # indicator
            Dict[
                str,  # port
                List[CofenseThreat],
            ],
        ]
        result = pydantic.parse_raw_as(result_type, resp.text)
        for indicator, ports in result.items():
            for port, entries in ports.items():
                for entry in entries:
                    yield entry



    


class CofenseThreat(BaseModel):
    """Result item"""

    threatId: int
    threatType: str
    occurredOn: datetime
    deleted: bool
    indicatorLog: indicatorLog



