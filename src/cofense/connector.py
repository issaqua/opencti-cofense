"""ThreatAPI connector"""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import date, datetime
from pathlib import Path
from typing import NamedTuple, Optional

import pycti
import stix2
import yaml
from pycti import Indicator
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from stix2.v21 import _Observable as Observable  # noqa

from .client import CofenseClient, CofenseUpdateChangelogItem
from .config import RootConfig
from .loop import ConnectorLoop

__all__ = [
    "CofenseConnector",
]

log = logging.getLogger(__name__)


class CofenseConnector:
    """Cofense ThreatHQ connector"""

    def __init__(self):
        """Constructor"""

        config_path = Path(__file__).parent.parent.joinpath("config.yml")
        config = (
            yaml.load(config_path.open(), Loader=yaml.SafeLoader)
            if config_path.is_file()
            else {}
        )

        self._config = RootConfig.parse_obj(config)
        self._helper = OpenCTIConnectorHelper(config)

        self._identity = self._helper.api.identity.create(
            type="Organization",
            name="Cofense",
            description="Cofense ThreatHQ",
        )
        self._identity_id = self._identity["standard_id"]

        self._client = CofenseClient(
            self._config.Cofense.api_url,
            self._config.Cofense.proxy_url,
            self._config.Cofense.proxy_user,
            self._config.Cofense.proxy_pass,
            self._config.Cofense.api_user,
            self._config.Cofense.api_pass,
            self._config.Cofense.ssl_verify
        )
        self._loop = ConnectorLoop(
            self._helper,
            self._config.connector.interval,
            self._config.connector.loop_interval,
            self._process_feed,
            True
        )

    def start(self) -> None:
        """Start the connector"""

        self._loop.start()
        self._loop.join()

    def _process_feed(self, work_id: str, timestamp: datetime) -> None:
        """
        Process the external connector feed.

        :param work_id: Work ID
        :return: None
        """

        log.info("The process feed timestamp is: " + str(timestamp))

        bundle_objects = []

        changelogs: List[CofenseUpdateChangelogItem]
        changelogs = self._client.queryUpdates(timestamp)

        log.info("2. We found [" + str(len(changelogs)) + "] changelog items.")

        for changelog in changelogs:
            if changelog.deleted:
                log.info("Threat id [" + str(changelog.threatId) + "] is a deleted changelog")
                continue
            else:
                log.info("Threat id [" + str(changelog.threatId) + "] is active.")

            stix2result = self._client.queryThreat(changelog.threatType, changelog.threatId)
            
            if stix2result is None or not stix2result or stix2result == "":
                log.info("The stix2result is None/empty")
                continue

            bundle_objects = json.loads(stix2result)["objects"]

            self._helper.send_stix2_bundle(
                bundle=stix2.Bundle( 
                    objects=bundle_objects,
                    allow_custom=True,
                ).serialize(),
                update=self._config.connector.update_existing_data,
                work_id=work_id,
                )
