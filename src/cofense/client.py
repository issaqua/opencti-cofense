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
from datetime import datetime, timedelta
from typing import Dict, Iterator, List

from stix2elevator import elevate
from stix2elevator.options import initialize_options, set_option_value

import re
import pydantic
import requests
import urllib3.exceptions
from pydantic import BaseModel
from requests import Response

__all__ = [
    "CofenseClient",
    "CofenseUpdateChangelogItem",
    "CofenseUpdateData",
    "CofenseUpdateModel",
]

log = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CofenseClient:

    def __init__(self, url: str, proxy_url: str, proxy_user: str, proxy_pass:str, api_user: str, api_pass: str, ssl_verify: bool = True):       
        """
        Constructor.
        :param url: Cofense ThreatHQ url  (default https://www.threathq.com/apiv1/)
        :param proxy_url: HTTP(S) proxy 
        :param proxy_user: HTTP(S) proxy username
        :param proxy_password: HTTP(S) proxy password
        :param api_user:  Cofense ThreatHQ API username
        :param api_pass: Cofense ThreatHQ API password
        :param ssl_verify: Verify SSL connections
        """    

        log.info("Made it to CofenseClient.__init__")

        if not url:
            raise ValueError("Cofense ThreatHQ URL must be set")

        self._api_url = url
        
        if proxy_url:
            if proxy_user and proxy_pass:
                proxy = re.sub('^https?:\/\/','', proxy_url)
                proxy = "https://{}:{}@{}".format(proxy_user, proxy_pass, proxy)
                proxy_url = { 'https' : proxy_url } # only support https proxy
            else:
                proxy_url = { 'https' : proxy_url } # only support https proxy
        self._verify = ssl_verify

        if not api_user or not api_pass:
            raise ValueError("Cofense ThreatHQ API id and key must be set")

        self._api_url = url
        self._session = requests.Session()
        if proxy_url:
            self._session.proxies.update(proxy_url)
        self._session.auth = (api_user, api_pass)
        self._session.verify = ssl_verify


    def queryUpdates(self, stamp: datetime) -> Iterator[CofenseUpdateChangelogItem]:
        """
        Process the feed URL and return any indicators.
        :return: Feed results
        """

        log.info("Made it to CofenseClient.queryUpdates")

        maxTimeDelta = datetime.utcnow() - timedelta(days = 365) # set to max one year ago (not bothering with leap years)

        if stamp is None or DateTime.LessThan(stamp, maxTimeDelta):
            stamp = datetime.utcnow() - timedelta(days = 365) # set to max one year ago (not bothering with leap years)
            
        self._session.params = { 'resultsPerPage': 100, 'sinceLastPublished': stamp.timestamp()}
        
        resp: Response = self._session.get(self._api_url + '/indicator/search')
        resp.raise_for_status()

        result_type = CofenseUpdateModel # Used https://jsontopydantic.com/ to build the models
        result = pydantic.parse_raw_as(result_type, resp.text)
        
        cofenseResult = result.items()

        ### Note if using /threat/updates
        cofenseData = cofenseResult["data"]
        cofenseChangelog = cofenseData["changelog"]
        for changelog in cofenseChangelog:
            for change in changelog:
                yield change
    
        ### Note if using /indicators/search
        #cofenseData = cofenseResult["data"]
        #cofenseIndicators = cofenseData["indicators"]
        #for indicator in cofenseIndicators:
        #    yield indicator

    def queryThreat(self, threatType: str, threatId: int):
        """
        Process stix1 format threat data for a given threatId .
        :param threatType: The type of threat we're processing (malware or phish)
        :param threatId: The threat id we're going to get the stix1 data for.
        :return: stix2 formatted threat data
        """
        
        log.info("Made it to CofenseClient.queryThreat")

        initialize_options(options={"spec_version": "2.1"})

        resp: Response = self._session.get(self._api_url + '/t3/' + threatType + '/' + threatId + '/stix')
        resp.raise_for_status()

        stix2result = elevate(resp.text)
        return stix2result




### Note if using indicators/search
#class CofensePage(BaseModel):
#    currentPage: int
#    currentElements: int
#    totalPages: int
#    totalElements: int

#class CofenseIndicator(BaseModel):
#    ioc: str
#    impact: str
#    indicator_type: str
#    threat_id: int
#    report_type: str
#    role: str

#class CofenseData(BaseModel):
#    page: CofensePage
#    indicators: List[CofenseIndicator]


#class CofenseModel(BaseModel):
#    success: bool
#    data: CofenseData    

### note if using /threat/updates
class CofenseUpdateChangelogItem(BaseModel):
    threatId: int
    threatType: str
    occurredOn: int
    deleted: bool

class CofenseUpdateData(BaseModel):
    nextPosition: str
    changelog: List[CofenseUpdateChangelogItem]

class CofenseUpdateModel(BaseModel):
    success: bool
    data: CofenseUpdateData