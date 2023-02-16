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

import html
import xml.etree.ElementTree as ET


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

        self._session = requests.Session()

        self._api_url = url
        
#        if proxy_url:
#            if proxy_user and proxy_pass:
#                proxy = re.sub('^https?:\/\/','', proxy_url)
#                proxy = "https://{}:{}@{}".format(proxy_user, proxy_pass, proxy)
#                proxy_url = { 'https' : proxy_url } # only support https proxy
#            else:
#                proxy_url = { 'https' : proxy_url } # only support https proxy
#        
#            self._session.proxies.update(proxy_url)
        
        self._ssl_verify = ssl_verify
        self._session.verify = ssl_verify

        if not api_user or not api_pass:
            raise ValueError("Cofense ThreatHQ API id and key must be set")

        self._session.auth = (api_user, api_pass)


        


    def queryUpdates(self, stamp: datetime) -> List[CofenseUpdateChangelogItem]:  # could change to list of these
        """
        Process the feed URL and return any indicators.
        :return: Feed results
        """

        log.info("Made it to CofenseClient.queryUpdates")
        log.info("1. stamp is " + str(stamp))

        maxTimeDelta = datetime.utcnow() - timedelta(days = 180) # set to max one year ago (not bothering with leap years)

        if stamp is None or (stamp < maxTimeDelta):
            stamp = maxTimeDelta # set to max one year ago (not bothering with leap years)

        log.info("2. stamp is " + str(stamp))

        epochSecs = round((stamp - datetime(1970,1,1)).total_seconds())  # need a better option here.

        log.info("3. epochSecs is " + str(epochSecs))

        self._session.params = { 'timestamp': epochSecs } 
        
        resp: Response = self._session.post(self._api_url + '/threat/updates')
        resp.raise_for_status()

#        result_type = CofenseUpdateModel # Used https://jsontopydantic.com/ to build the models

        cofenseUpdateResult: CofenseUpdateModel
        cofenseUpdateResult = pydantic.parse_raw_as(CofenseUpdateModel, resp.text)
        
#### NOTE: I have to make this process handle multiple pages!!

        if not cofenseUpdateResult.success:  # we failed somehow.
            log.info("Success was not true")
            return
        
        cofenseUpdateData: CofenseUpdateData
        cofenseUpdateData = cofenseUpdateResult.data

        cofenseUpdateChangelog: List[CofenseUpdateChangelogItem]
        cofenseUpdateChangelog = cofenseUpdateData.changelog

        # have to handle condition where there are no results.  # TODO: Check caller can handle None result.
        if cofenseUpdateChangelog is [] or cofenseUpdateChangelog is None:
            log.info("There were no threat updates.")
            return  ## TODO: Not sure if this is the right way to break out of the iteration.

        log.info("1. We found [" + str(len(cofenseUpdateChangelog)) + "] changelog items.")
        return cofenseUpdateChangelog  # For each changelog item
            
    def queryThreat(self, threatType: str, threatId: int):
        """
        Process stix1 format threat data for a given threatId .
        :param threatType: The type of threat we're processing (malware or phish)
        :param threatId: The threat id we're going to get the stix1 data for.
        :return: stix2 formatted threat data
        """
        
        log.debug("Made it to CofenseClient.queryThreat: Type=" + threatType + "and threatId=" + str(threatId) )

        resp: Response = self._session.get(self._api_url + '/t3/' + threatType + '/' + str(threatId) + '/stix')
        resp.raise_for_status()
        
        if resp.text is None or not resp.text or resp.text == "" or resp.text.isspace():
            log.debug("Response text is None/Empty")
            return
        else:
            log.debug("Response text is" + resp.text)

            try:
                initialize_options()
                stix2result = elevate(resp.content)
            except Exception as ex:
                log.exception("Unhandled exception in connector loop: %s", ex)
                return

            log.debug("Returning stix2result")

            return stix2result


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