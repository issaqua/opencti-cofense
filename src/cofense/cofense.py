"""
Copyright 2013-2015 Cofense, Inc.  All rights reserved.

This software is provided by Cofense, Inc. ("Cofense") on an "as is" basis and any express or implied warranties,
including but not limited to the implied warranties of merchantability and fitness for a particular purpose, are
disclaimed in all aspects.  In no event will Cofense be liable for any direct, indirect, special, incidental or
consequential damages relating to the use of this software, even if advised of the possibility of such damage. Use of
this software is pursuant to, and permitted only in accordance with, the agreement between you and Cofense.

Cofense Base Module (for both Python 2.x & Python 3.x)
Author: Josh Larkins/Kevin Stilwell/Robert McMahon
Support: support@cofense.com
ChangesetID: CHANGESETID_VERSION_STRING

"""

try:
    from configparser import ConfigParser
    PYTHON_MAJOR_VERSION = 3
except ImportError:
    from ConfigParser import SafeConfigParser
    PYTHON_MAJOR_VERSION = 2

from calendar import timegm
from datetime import datetime
import time
import json
import logging
import os
import sys
import re
import argparse

import requests


LOGGER = logging.getLogger('cofense')


class CofenseConnectionType():
    THREAT_SEARCH = 1
    THREAT_UPDATES = 2
    T3_CEF = 3
    T3_STIX = 4


def connect_to_cofense(config, auth, url, verb, params=None, proxies=None, headers=None):
    """
    Make a connection to Cofense API and return the content of a successful request.

    :param config:
    :param auth:
    :param url:
    :param verb:
    :param params:
    :param proxies:
    :return:
    """

    # Try each request up to 3 times before failing.
    max_attempts = 3

    for _ in range(max_attempts):
        try:
            LOGGER.info('Requesting data from ThreatHQ')
            if verb == 'GET':
                response = requests.get(url=url, params=params, auth=auth, proxies=proxies, headers=headers)
            elif verb == 'POST':
                response = requests.post(url=url, params=params, auth=auth, proxies=proxies, headers=headers)
            else:
                raise ValueError('The HTTP verb must be GET or POST not: %s' % verb)

            LOGGER.info('Got a %d response' % response.status_code)

            if response.status_code == 400:
                raise ValueError('HTTP Status: ' + str(response.status_code) + '  Message: Bad request due to malformed syntax.')
            elif response.status_code == 401:
                raise ValueError('HTTP Status: ' + str(response.status_code) + '  Message: Failed to authorize.')
            elif response.status_code == 404:
                raise ValueError('HTTP Status: ' + str(response.status_code) + '  Message: Requested data not found.')
            elif str(response.status_code).startswith('5'):
                raise ValueError('HTTP Status: ' + str(response.status_code) + '  Message: Server error.')
            elif response.status_code != 200:
                raise ValueError('HTTP Status: ' + str(response.status_code) + '  Message: Connection error.')
            

        except requests.exceptions.ChunkedEncodingError as exception:
            LOGGER.error('An error occurred during the previous request. Results are as follows:  Message: Chunked Encoding Error.')
            remove_lock_and_exit(config, 1)

        except requests.exceptions.Timeout as exception:
            LOGGER.error('An error occurred during the previous request. Results are as follows:  Message: Request timeout.')
            remove_lock_and_exit(config, 2)

        except requests.exceptions.TooManyRedirects as exception:
            LOGGER.error('An error occurred during the previous request. Results are as follows:  Message: Too many requests.')
            remove_lock_and_exit(config, 3)

        except requests.exceptions.RequestException as exception:
            LOGGER.error('An error occurred during the previous request. Results are as follows: Message: Request exception. %s' % exception)
            remove_lock_and_exit(config, 4)

        except ValueError as exception:
            LOGGER.error('An error occurred during the previous request. Results are as follows: ' + exception.args[0])
            remove_lock_and_exit(config, 5)

        else:
            LOGGER.debug('Request was successful.')
            return response.content

    else:
        LOGGER.error('An error occurred. Tried to complete request ' + str(max_attempts) + ' times and all failed.')
        remove_lock_and_exit(config, 6)


def retrieve_from_threat_updates(config, end_timestamp):
    """
    Handle output from Cofense's /threat/updates
    """

    # Setup
    auth, url, proxies, headers = setup_cofense_connection(CofenseConnectionType.THREAT_UPDATES, config)

    # If the position UUID does not exist, then the integration has been initialized during this execution and we need to provide that end_timestamp to
    # /threat/updates to receive back a position UUID. Otherwise, we provide the current position from the config file.
    if config.get('cofense', 'position'):
        payload = {'position': config.get('cofense', 'position')}
    else:
        payload = {'timestamp': end_timestamp}

    # Logging
    if config.get('cofense', 'position'):
        LOGGER.info('Retrieving ' + url + ' with position: ' + payload.get('position'))
    else:
        LOGGER.info('Retrieving ' + url + ' with end_timestamp: ' + str(end_timestamp))

    # Connect to Cofense
    response = connect_to_cofense(config=config, auth=auth, url=url, params=payload, proxies=proxies, verb='POST', headers=headers)

    LOGGER.debug('Results retrieved.')
    # Extract and return appropriate response.

    try:
        if PYTHON_MAJOR_VERSION == 3:
            result = json.loads(response.decode())
        else:
            result = json.loads(response)
    except Exception as e:
        LOGGER.error("There was an error decoding the response to json: %s" % e)
        LOGGER.debug(response)

        raise e
        
    changelog = result.get('data').get('changelog')
    changelog_size = len(changelog)
    next_position = result.get('data').get('nextPosition')

    malware_add_set = set()
    phish_add_set = set()
    malware_remove_set = set()
    phish_remove_set = set()

    LOGGER.debug('Changelog size: %d' % len(changelog))
    # Iterate through results and grab each result in desired format
    for update in changelog:
        threat_id = str(update.get('threatId'))
        threat_type = update.get('threatType')
        deleted = update.get('deleted')
        
        LOGGER.debug('Processing threat_id: %s, threat_type: %s, deleted: %s' % (threat_id, threat_type, deleted))

        # These are new or modified items
        if not deleted:
            if threat_type == 'malware':
                LOGGER.debug('Adding threat_id: %s to the malware_add_set' % threat_id)
                malware_add_set.add(threat_id)
            elif threat_type == 'phish':
                LOGGER.debug('Adding threat_id: %s to the phish_add_set' % threat_id)
                phish_add_set.add(threat_id)
            else:
                LOGGER.debug('Not adding entry with threat type %s' % threat_type)
        # These are items that should be deleted
        else:
            if threat_type == 'malware':
                LOGGER.debug('Adding malware to malware_remove_set threat_id:%s' % threat_id)
                malware_remove_set.add(threat_id)
            elif threat_type == 'phish':
                LOGGER.debug('Adding phish to phish_remove_set threat_id: %s' % threat_id)
                phish_remove_set.add(threat_id)
            else:
                LOGGER.debug('Not adding entry with threat type %s' % threat_type)
    LOGGER.debug('changelog_size: %d, malware_add_size: %d, phish_add_size: %d, malware_remove_size: %d, phish_remove_size: %s' % (changelog_size, len(malware_add_set), len(phish_add_set), len(malware_remove_set), len(phish_remove_set)))
    return next_position, changelog_size, malware_add_set, phish_add_set, malware_remove_set, phish_remove_set


def retrieve_from_t3_cef(config, payload=None, threat_type=None, threat_id=None):
    """
    Handle output from Cofense's /t3/{threat_type}/{threat_id}/cef.
    """

    # Setup
    auth, url, proxies, headers = setup_cofense_connection(CofenseConnectionType.T3_CEF, config, threat_type, threat_id)

    # Logging
    LOGGER.debug('Retrieving ' + url)

    # Connect to Cofense
    if payload:
        response = connect_to_cofense(config=config, auth=auth, url=url, params=payload, proxies=proxies, verb='POST', headers=headers)
    else:
        response = connect_to_cofense(config=config, auth=auth, url=url, proxies=proxies, verb='GET', headers=headers)

    # Extract and return appropriate response.
    return response


def retrieve_from_t3_stix(config, threat_type=None, threat_id=None):
    """
    Handle output from Cofense's /t3/{threat_type}/{threat_id}/stix.
    """

    # Setup
    auth, url, proxies, headers = setup_cofense_connection(CofenseConnectionType.T3_STIX, config, threat_type, threat_id)

    # Logging
    LOGGER.debug('Retrieving STIX from ' + url)

    # Connect to Cofense
    response = connect_to_cofense(config=config, auth=auth, url=url, proxies=proxies, verb='GET', headers=headers)

    # Extract and return appropriate response.
    return response


def get_threats_from_search(config, payload, total_pages=1):
    """
    Wrapper for retrieve_from_threat_search 
    """
    threats = []
    try:
        total_pages, threats = retrieve_from_threat_search(config,payload)
    except Exception as e:
        LOGGER.error(e)
        LOGGER.info('There was an error getting a batch of threats from the search endpoint, attempting to get threats one by one to identify the culprit')

        if 'threatId' in payload:
            threat_ids = payload['threatId']
            if isinstance(threat_ids, list):
                for threat_id in threat_ids:
                    payload['threatId'] = threat_id
                    try:
                        _, t = retrieve_from_threat_search(config, payload)
                        if isinstance(t, list):
                            threats.extend(t)
                        else:
                            threats.append(t)
                    except Exception as e:
                        LOGGER.info("Hit an error on threat_id: {}".format(threat_id))
                        LOGGER.error(e)
                        continue
                return total_pages, threats

        elif 'page' in payload and 'resultsPerPage' in payload:
            page_number = int(payload.get('page'))
            results_per_page = int(payload.get('resultsPerPage'))

            begin_page_number = page_number * results_per_page

            for i in range(0, results_per_page):
                payload['resultsPerPage'] = 1
                payload['page'] = begin_page_number + i
                LOGGER.info("resultsPerPage: {}, page: {}".format(payload['resultsPerPage'], payload['page']))
                try:
                    _, t = retrieve_from_threat_search(config, payload)
                    if isinstance(t, list):
                        threats.extend(t)
                    else:
                        threats.append(t)
                except Exception as e:
                    LOGGER.info("Hit the error on page: {}".format(payload['page']))
                    LOGGER.error(e)
                    continue

    return total_pages, threats


def retrieve_from_threat_search(config, payload):
    """
    Handle output from Cofense's /threat/search
    """
    LOGGER.debug('Searching ThreatHQ for %s' % str(payload))
    # Setup
    auth, url, proxies, headers = setup_cofense_connection(CofenseConnectionType.THREAT_SEARCH, config)

    # Logging
    if payload.get('page') and payload.get('beginTimestamp') and payload.get('endTimestamp'):
        LOGGER.info('Retrieving JSON from ' + url + ' for window from ' + str(datetime.fromtimestamp(payload.get('beginTimestamp'))) + ' to ' + str(datetime.fromtimestamp(payload.get('endTimestamp'))) + '. Retrieving page ' + str(payload.get('page')) + '...')

    elif payload.get('beginTimestamp') and payload.get('endTimestamp'):
        LOGGER.info('Retrieving JSON from ' + url + ' for window from ' + str(datetime.fromtimestamp(payload.get('beginTimestamp', ''))) + ' to ' + str(datetime.fromtimestamp(payload.get('endTimestamp', ''))))

    else:
        LOGGER.info('Retrieving JSON from {} for {} threats'.format(url, len(payload.get('threatId')) if isinstance(payload.get('threatId'), list) else 1))

    # Connect to Cofense
    response = connect_to_cofense(config=config, auth=auth, url=url, params=payload, proxies=proxies, verb='POST', headers=headers)

    # Extract and return appropriate response.
    if PYTHON_MAJOR_VERSION == 3:
        result = json.loads(response.decode())
    else:
        result = json.loads(response)

    if "success" in result and result['success']:
        LOGGER.debug('Retrieved ' + str(len(result.get('data').get('threats'))) + ' threats, processing.')
        return result.get('data').get('page').get('totalPages'), result.get('data').get('threats')
    else:
        if "success" in result:
            raise Exception("The result returned from the web server was: {}".format())
        else:
            raise Exception("The result from the api returned with no success attribute")

def add_to_proxies_dict(proxy_http,user_auth_string):
    if user_auth_string:
        proxy_http = re.sub('^https?:\/\/','', proxy_http)
        proxy_http = "http://{}@{}".format(user_auth_string,proxy_http)
    return proxy_http
    

def check_threat_type(threat_id,threat_type):
    if threat_type and threat_id:
        url_values = '/t3/' + threat_type + '/' + threat_id + '/cef'
    else:
        url_values = '/t3/cef'
    return url_values

def setup_cofense_connection(connection_type, config, threat_type=None, threat_id=None):
    """
    This method will handle connection setup tasks for the various types of queries
    :param connection_type: CofenseConnectionType
    :param config: connection configuration
    :param threat_type: Type of threat to search for (Threat Search and Threat Updates only)
    :param threat_id: ID of threat to search for (Threat Search and Threat Updates only)
    :return:
    """

    if connection_type is CofenseConnectionType.THREAT_SEARCH:
        url_values = '/threat/search'
    elif connection_type is CofenseConnectionType.THREAT_UPDATES:
        url_values = '/threat/updates'
    elif connection_type is CofenseConnectionType.T3_CEF:
        url_values = check_threat_type(threat_id,threat_type)
    elif connection_type is CofenseConnectionType.T3_STIX:
        if threat_type and threat_id:
            url_values = '/t3/' + threat_type + '/' + threat_id + '/stix'
    else:
        raise Exception("Connection type not one of THREAT_SEARCH, THREAT_UPDATES, T3_CEF, or T3_STIX")

    url = config.get('cofense', 'base_url') + url_values
    auth = (config.get('cofense', 'user'), config.get('cofense', 'pass'))
    proxies = {}
    user_auth_string = None
    if config.has_option('proxy', 'auth_basic_user'):
        user_auth_string = "{}:{}".format(config.get('proxy', 'auth_basic_user'), config.get('proxy', 'auth_basic_pass'))

    if config.has_option('proxy', 'http'):
        proxy_http = config.get('proxy', 'http')
        proxy_http = add_to_proxies_dict(proxy_http,user_auth_string)
        proxies['http'] = proxy_http

    if config.has_option('proxy', 'https'):
        proxy_https = config.get('proxy', 'https')
        if user_auth_string:
            proxy_https = re.sub('^https?:\/\/','',proxy_https)
            proxy_https = "https://{}@{}".format(user_auth_string, proxy_https)
        proxies['https'] = proxy_https

    user_agent = 'Cofense Intelligence Splunk Integration'
    if config.has_option('integration','version'):
        user_agent += ' v{}'.format(config.get('integration','version'))

    headers = {'User-Agent': user_agent}

    return auth, url, proxies, headers


def initial_time_window(num_days):
    """
    Return a time window in seconds based on the input number of days.
    """

    now = time.time()

    if PYTHON_MAJOR_VERSION == 3:
        return round(now - (num_days * 24 * 60 * 60)), round(now)
    else:
        return int(now - (num_days * 24 * 60 * 60)), int(now)


def date_to_epoch(date):
    """

    :param num_days:
    :return:
    """
    utc_time = time.strptime(date, '%Y-%m-%d')
    epoch_time = timegm(utc_time)
    return int(epoch_time), int(time.time())


def read_args(script_description):
    """ Parse all input arguments.
    """

    parser = argparse.ArgumentParser(description=script_description)

    # Arguments to parse.
    parser.add_argument('-conf', '--config_file', help='Config location. By default, config file is assumed to be in the same directory and named \'config.ini\'.', required=False, default='config.ini')
    parser.add_argument('-type', '--threat_type', help='Type of threats to retrieve. Choices are \'all\', \'malware\', or \'phish\'.', required=False, default='all', choices=['all', 'malware', 'phish'])

    return parser.parse_args()


def read_config(config_file):
    """
    Read configuration file.
    """

    if PYTHON_MAJOR_VERSION == 3:
        config = ConfigParser()
    else:
        config = SafeConfigParser()

    config.read(config_file)

    return config


###
# Check for concurrency
def add_lock(config):
    """
    Create lock file if it does not exit; exit if lock file already exists.
    """

    # Lock file is required for this execution
    if config.getboolean('concurrency', 'use') is True:
        lock_file_full_path = config.get('concurrency', 'lock_file')

        # Try to open the lock file. It probably won't exist, so an error will be thrown. This is normal.
        try:
            open(lock_file_full_path)

            # If still in this block, then the lock file must already exist.
            LOGGER.warning('File locked: ' + lock_file_full_path + '. This instance will exit.')
            return False

        # A lock file doesn't exist - create one.
        except (IOError, OSError):

            # Create lock file.
            try:
                with open(lock_file_full_path, 'w+'):
                    return True

            # Could not create a lock file. Likely a permissions error.
            except (IOError, OSError):
                LOGGER.error('Could not create lock file at: ' + lock_file_full_path + '. This is most likely a permissions issue.')
                return False

    # Lock file not required for this execution.
    else:
        return True


###
# Remove lock file
def remove_lock_and_exit(config, exit_code=0):
    """
    Remove lock file and exit.
    """

    if config.getboolean('concurrency', 'use') is True:
        lock_file_full_path = config.get('concurrency', 'lock_file')
        os.remove(lock_file_full_path)

        if exit_code == 0:
            LOGGER.warn('Exiting.\n\n')
        else:
            LOGGER.warn('Exiting due to failure.\n\n')
        sys.exit(exit_code)
