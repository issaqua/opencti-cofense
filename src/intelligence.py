"""
Copyright 2013-2016 Cofense, Inc.  All rights reserved.

This software is provided by Cofense, Inc. ("Cofense") on an "as is" basis and any express or implied warranties,
including but not limited to the implied warranties of merchantability and fitness for a particular purpose, are
disclaimed in all aspects.  In no event will Cofense be liable for any direct, indirect, special, incidental or
consequential damages relating to the use of this software, even if advised of the possibility of such damage. Use of
this software is pursuant to, and permitted only in accordance with, the agreement between you and Cofense.

Cofense Base Module (for both Python 2.x & Python 3.x)
Author: Josh Larkins/Kevin Stilwell
Support: support@cofense.com
ChangesetID: CHANGESETID_VERSION_STRING

"""



NOTRECORDED="Not recorded by Cofense"

class Malware(object):
    """
    Malware class holds a single malware campaign.
    """

    def __init__(self, malware):
        """
        Initialize Malware object.
        """

        self.threat_type = malware.get('threatType')
        self.block_set = malware.get('blockSet')
        self.brand = malware.get('campaignBrandSet', '')
        self.content = malware
        self.domain_set = malware.get('domainSet')
        self.executable_set = malware.get('executableSet')
        self.first_published = malware.get('firstPublished')
        self.last_published = malware.get('lastPublished')
        self.malware_family = malware.get('malwareFamilySet', '')
        self.sender_ip_set = malware.get('senderIpSet')
        self.spam_url_set = malware.get('spamUrlSet')
        self.subject_set = malware.get('subjectSet')
        self.sender_email_set = malware.get('senderEmailSet')
        self.active_threat_report = malware.get('reportURL')
        self.active_threat_report_api = malware.get('apiReportURL')
        self.threathq_url = malware.get('threatDetailURL')
        self.threat_id = malware.get('id')
        self.label = malware.get('label')

    def get_content(self):
        """
        Return content.
        """
        return self.content

    def get_threat_type(self):
        return self.threat_type

    def get_threat_id(self):
        """
        Return Threat ID.
        """
        return self.threat_id

    def get_label(self):
       """
       Return label.
       """
       return self.label

    def get_malware_family(self):
        """
        Return comma-separated list of malware families.
        """
        if self.malware_family:
            family_temp = []
            for family in self.malware_family:
                family_temp.append(family.get('familyName'))
            return ', '.join(family_temp)
        else:
            return ' '

    def get_threathq_url(self):
        """
        Return ThreatHQ URL.
        """
        return self.threathq_url

    def get_active_threat_report_url(self):
        """
        Return Active Threat Report URL for regular customer access.
        """
        return self.active_threat_report

    def get_active_threat_report_api_url(self):
        """
        Return Active Threat Report URL for API access.
        """
        return self.active_threat_report_api

    def get_brand(self):
        """
        Return comma-separated list of brands.
        """
        if self.brand:
            brand_temp = []
            for brand in self.brand:
                brand_temp.append(brand.get('brand').get('text'))
            return ', '.join(brand_temp)
        else:
            return ' '

    def get_last_published(self):
        """
        Return last published date.
        """
        return self.last_published

    def get_first_published(self):
        """
        Return first published date.
        """
        return self.first_published

    def get_block_set(self):
        """
        Return block set.
        """
        return self.block_set

    def get_executable_set(self):
        """
        Return executable set.
        """
        return self.executable_set

    def get_domain_set(self):
        """
        Return domain set.
        """
        return self.domain_set

    def get_sender_ip_set(self):
        """
        Return sender IP set.
        """
        return self.sender_ip_set

    def get_spam_url_set(self):
        """
        Return spam URL set.
        """
        return self.spam_url_set

    def get_subject_set(self):
        """
        Return subject set.
        """
        return self.subject_set

    def get_sender_email_set(self):
        """
        Return sender_email set.
        """
        return self.sender_email_set

    class BlockSet(object):
        """
        BlockSet
        """

        def __init__(self, block_set):
            """
            Initialize BlockSet object
            """
            self.block_type = block_set.get('blockType')
            self.impact = block_set.get('impact')
            self.role = block_set.get('role', NOTRECORDED)
            self.role_description = block_set.get('roleDescription', NOTRECORDED)

            try:
                self.malware_family = block_set.get('malwareFamily').get('familyName')
            except AttributeError:
                self.malware_family = NOTRECORDED

            try:
                self.malware_family_description = block_set.get('malwareFamily').get('description')
            except AttributeError:
                self.malware_family_description = NOTRECORDED

            if self.block_type == 'URL':
                self.watchlist_ioc = block_set.get('data_1').get('url')
                self.watchlist_host = block_set.get('data_1').get('host')
                self.watchlist_path = block_set.get('data_1').get('path')
            else:
                self.watchlist_ioc = block_set.get('data_1')

    class ExecutableSet(object):
        """
        ExecutableSet
        """

        def __init__(self, executable_set):
            """
            Initialize ExecutableSet object
            """

            self.file_name = executable_set.get('fileName')
            self.type = executable_set.get('type', NOTRECORDED)
            self.md5 = executable_set.get('md5Hex')

            try:
                self.malware_family = executable_set.get('malwareFamily').get('familyName')
            except AttributeError:
                self.malware_family = NOTRECORDED

            try:
                self.malware_family_description = executable_set.get('malwareFamily').get('description')
            except AttributeError:
                self.malware_family_description = NOTRECORDED

            try:
                self.subtype = executable_set.get('executableSubtype').get('description')
            except AttributeError:
                self.subtype = NOTRECORDED

    class SubjectSet(object):
        """
        SubjectSet
        """

        def __init__(self, subject_set):
            """
            Initialize SubjectSet object
            """

            self.subject = subject_set.get('subject')
            self.total_count = subject_set.get('totalCount')

    class SenderIPSet(object):
        """
        SenderIPSet
        """

        def __init__(self, sender_ip_set):
            """
            Initialize SenderIPSet object
            """

            self.ip = sender_ip_set.get('ip')
            self.total_count = sender_ip_set.get('totalCount')

    class SenderEmailSet(object):
        """
        SenderEmailSet
        """

        def __init__(self, sender_email_set):
            """
            Initialize SenderEmailSet object
            """

            self.sender_email = sender_email_set.get('senderEmail')
            self.total_count = sender_email_set.get('totalCount')
