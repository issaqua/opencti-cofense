# Copyright 2013-2017 Cofense, Inc.  All rights reserved.
#
# This software is provided by Cofense, Inc. ("Cofense") on an "as is" basis and any express or implied warranties,
# including but not limited to the implied warranties of merchantability and fitness for a particular purpose, are
# disclaimed in all aspects.  In no event will Cofense be liable for any direct, indirect, special, incidental or
# consequential damages relating to the use of this software, even if advised of the possibility of such damage. Use of
# this software is pursuant to, and permitted only in accordance with, the agreement between you and Cofense.
from __future__ import unicode_literals, absolute_import
import logging


# Logging set up

class Phish(object):
    """
    Phish class holds a single Cofense Brand Intelligence object.
    """
    def __init__(self, phish):
        """
        Initialize a Cofense Brand Intelligence object.

        :param str phish:
        """

        self.json = phish
        """
        The raw JSON used the create the :class:`cofense_intelligence.core.brand_intelligence.Phish` object.
 
        :return: String representation of this object.
        :rtype: str
        """

        self.confirmed_date = phish.get('confirmedDate')
        """
        The time when the phish was confirmed as being a phishing threat.
        
        :return: A timestamp in epoch milliseconds.
        :rtype: int
        """

        self.first_published = phish.get('firstDate')
        """
        The first time this phishing URL was ingested by Cofense
        
        :return: A timestamp in epoch milliseconds.
        :rtype: int
        """

        self.last_published = phish.get('lastDate')
        """
        The most recent time this phishing URL was reported to Cofense. Note, if a phishing URL already processed by 
        Cofense is seen again, retrieval of content found at that phishing URL is not performed. Only this timestamp 
        is updated.
        
        :return: A timestamp in epoch milliseconds.
        :rtype: int
        """

        self.threathq_url = phish.get('threatDetailURL')
        """
        A direct URL to the Cofense Intelligence portal for this specific Threat ID.

        :return: URL to this Threat ID in Cofense Intelligence portal.
        :rtype: str
        """

        self.threat_id = phish.get('id')
        """
        A unique identifier across all phishing attacks recorded by Cofense.

        :return: A numeric identifier for a phishing attack.
        :rtype: str
        """

        self.web_components = phish.get('webComponents')
        """
        .. _web_components:
        
        These are the web components used to build a phishing website within a victim's browser. This collection of 
        files can include files like javascrpt, cascading style sheets, or images hosted by the legitimate website of 
        the targeted brand. These cases are excellent opportunities for the targeted brand to retrieve referral logs 
        which will reveal the victim's IP as they access a phishing site. Criminals may choose to reference these files 
        hosted by the legitimate website for simplicity or to keep the look and feel of their phishing site equivalent 
        to the legitimate site they're imitating. These files are downloadable as a single encrypted archive.
        
        :return: list of web components as dictionary value 
        :rtype: list of dicts
        """
        self.kits = None
        """
        .. _kits:
        .. _kit_files:
        
        These are the phishing kits retrieved during our processing of a phishing site. These kits are downloadable 
        from ThreatHQ as a single encrypted archive. 
        
        Within this data is alsoEmail addresses found within a phishing kit. These are typically drop email addresses, 
        but may include any email addresses found within the body of the phishing kit. Reasons for the presence of a 
        non-drop email address include contact info for the phishing kit creator, contact info for the author of a 
        particular script within the phishing site, or the spoofed "from" email address that will be used to create the 
        email to the criminal. 
        
        :return: list of web components as dictionary value 
        :rtype: list of dicts
        """

        self.title = phish.get('title')
        """
        The text from the raw HTML used to display the phishing URL, typically found within the <title> </title> tags. 
        This is the text displayed by a browser at the top of the browser or tab.
        
        :return: The title text
        :rtype: str
        """

        self.language = phish.get('language')
        """
        The primary language used in the visible portions of the phishing site, as determined by an NLP library.
        
        :return: The language details about the phishing threat
        :rtype: dict
        """
        self.reported_url_list = None
        """
        .. _reported_urls:
        
        List of reported URLs. These are the original URLs reported to Cofense. They might be the same as the Phishing 
        URL or they might be a re-director of some type, either a compromised site or a shortened URL like bit.ly or 
        tinyurl. 
        
        :return: list of :class:`cofense_intelligence.core.brand_intelligence.URL`
        :rtype: list
        """

        self.phish_url = None
        """
        .. _phish_urls:
        
        These components represent the current location of a phishing page, whether hosted on a compromised website or 
        a domain specifically registered for phishing purposes.
        
        :return: :class:`cofense_intelligence.core.brand_intelligence.URL`
        :rtype: :class:`cofense_intelligence.core.brand_intelligence.URL` or None
        """

        self.action_url_list = None
        """
        .. _action_urls:
         
        This is the next URL to be called when the victim submits their information to the phishing site. It might lead 
        directly to a second page of the phishing site, it might be an intermediate PHP script that submits credentials 
        to the criminal, it might lead to an exit URL, or it may be some combination of these things. Note: each page of 
        a phishing attack will have an action URL, Cofense is only capturing the Action URL for the first page.
        
        :return: list of :class:`cofense_intelligence.core.brand_intelligence.URL`
        :rtype: list
        """

        self.screenshot_url = None
        """
        A screenshot captured of the phishing URL. If you were to visit the phishing URL directly, you should expect 
        the same visual experience as you see in this screenshot.       
        
        :return: :class:`cofense_intelligence.core.brand_intelligence.URL`
        :rtype: :class:`cofense_intelligence.core.brand_intelligence.URL` or None
        """

        self.brand = None
        """
        A list of brands (if any) being imitated by a particular phishing attack. Typically these will be online service
        providers
        
        :return: Comma-separated list of brands
        :rtype: str or None
        """

        self.ip = None
        """
        Information about the IP address associated with the phishing URL 
        
        :return: :class:`cofense_intelligence.core.brand_intelligence.IPv4`
        :rtype: :class:`cofense_intelligence.core.brand_intelligence.IPv4` or None
        """

        self.confirmation_data = None

    @property
    def confirmation_data(self):
        return self._confirmation_data

    @confirmation_data.setter
    def confirmation_data(self, value):
        if self.json.get('confirmationData'):
            self._confirmation_data = self.json.get('confirmationData')
        else:
            self._confirmation_data = None


    @property
    def kits(self):
        """

        :return:
        """

        return self._kits

    @kits.setter
    def kits(self, value):
        """

        :param value:
        :return:
        """
        return_list = []

        for item in self.json.get('kits'):
            return_list.append(self.Kit(item))

        self._kits = return_list

    @property
    def ip(self):
        """

        :return:
        """

        return self._ip

    @ip.setter
    def ip(self, value):
        """

        :param value:
        :return:
        """

        if self.json.get('ipDetail'):
            self._ip = IPv4(self.json.get('ipDetail'))
        else:
            self._ip = None

    @property
    def phish_url(self):
        """

        :return:
        """

        return self._phish_url

    @phish_url.setter
    def phish_url(self, value):
        """

        :param value:
        :return:
        """

        if self.json.get('phishingURL_1'):
            self._phish_url = URL(self.json.get('phishingURL_1'))
        else:
            self._phish_url = None

    @property
    def screenshot_url(self):
        """

        :return:
        """

        return self._screenshot_url

    @screenshot_url.setter
    def screenshot_url(self, value):
        """

        :param value:
        :return:
        """

        try:
            self._screenshot_url = URL(self.json.get('screenshot').get('url_1')).url

        # If we catch a PmAttributeError here, we miss the AttributeError being thrown when a screenshot URL is not available.
        except AttributeError:
            self._screenshot_url = None

    @property
    def reported_url_list(self):
        """

        :return:
        """

        return self._reported_url_list

    @reported_url_list.setter
    def reported_url_list(self, value):
        """

        :param value:
        :return:
        """

        return_list = []

        for item in self.json.get('reportedURLs_1'):
            return_list.append(URL(item))

        self._reported_url_list = return_list

    @property
    def action_url_list(self):
        """

        :return:
        """

        return self._action_url_list

    @action_url_list.setter
    def action_url_list(self, value):
        """

        :param value:
        :return:
        """

        return_list = []

        for item in self.json.get('actionURLs_1'):
            return_list.append(URL(item))

        self._action_url_list = return_list

    @property
    def brand(self):
        """

        :return:
        """

        return self._brand

    @brand.setter
    def brand(self, value):
        """
        Return comma-separated list of brands.
        """
        brand_temp = []

        if self.json.get('brands'):
            for brand in self.json.get('brands'):
                brand_temp.append(brand.get('text'))

            self._brand = ', '.join(brand_temp)

        else:
            self._brand = None

    class Kit(object):
        """
        Kit
        """

        def __init__(self, kit):
            """
            Initialize kit object.
            """

            self.json = kit
            self.kit_name = kit.get('kitName')
            self.size = kit.get('fileSize')
            self.md5 = kit.get('md5')
            self.sha1 = kit.get('sha1')
            self.sha224 = kit.get('sha224')
            self.sha256 = kit.get('sha256')
            self.sha384 = kit.get('sha384')
            self.sha512 = kit.get('sha512')
            self.ssdeep = kit.get('ssdeep')
            self.kit_files = None

        @property
        def kit_files(self):
            """

            :return:
            """

            return self._kit_files

        @kit_files.setter
        def kit_files(self, value):
            """

            :param value:
            :return:
            """

            return_list = []

            for item in self.json.get('files'):
                return_list.append(self.KitFile(item))

            self._kit_files = return_list

        class KitFile(object):
            """
            KitFile object.
            """

            def __init__(self, kit_file):
                """
                Initialize kit file.
                """

                self.json = kit_file
                self.file_name = kit_file.get('fileName')
                self.size = kit_file.get('size')
                self.path = kit_file.get('path')
                self.md5 = kit_file.get('md5')
                self.sha1 = kit_file.get('sha1')
                self.sha224 = kit_file.get('sha224')
                self.sha256 = kit_file.get('sha256')
                self.sha384 = kit_file.get('sha384')
                self.sha512 = kit_file.get('sha512')
                self.ssdeep = kit_file.get('ssdeep')
                self.observed_emails = None

            @property
            def observed_emails(self):
                """

                :return:
                """

                return self._emails

            @observed_emails.setter
            def observed_emails(self, value):
                """

                :param value:
                :return:
                """
                return_list = []

                for item in self.json.get('emails'):
                    return_list.append(self.Email(item))

                self._emails = return_list

            class Email(object):
                """
                Email object.
                """

                def __init__(self, observed_email):
                    """
                    Initialize email.
                    :return:
                    """

                    self.json = observed_email
                    self.email_address = observed_email.get('email')
                    self.obfuscation_type = observed_email.get('obfuscationType')


class IPv4(object):
    """

    """

    def __init__(self, ipv4):
        """

        :return:
        """
        if ipv4:
            self.json = ipv4
            """
            The raw JSON used to create the :class:`cofense_intelligence.core.brand_intelligence.IPv4` object.

            :return: String representation of this object.
            :rtype: str
            """

            self.asn = ipv4.get('asn')
            """
            The number which refers to a network operator 

            :return: The AS number.
            :rtype: int
            """

            self.asn_organization = ipv4.get('asnOrganization')
            """
            The long form name of the organization responsible for this ASN.

            :return: The organization name.
            :rtype: str
            """

            self.continent_code = ipv4.get('continentCode')
            self.continent_code = ipv4.get('continentCode')
            """
            Two-letter continent code. Watch out for 'AQ'.

            :return: The continent code.
            :rtype: str
            """

            self.continent_name = ipv4.get('continentName')
            """
            Continent name.

            :return: Continent name.
            :rtype: str
            """

            self.country_iso_code = ipv4.get('countryIsoCode')
            """
            `Two-letter country code. <http://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#Current_codes>`_

            :return: Two-letter country code.
            :rtype: str
            """

            self.country_name = ipv4.get('countryName')
            """
            Country name.

            :return: Country name.
            :rtype: str
            """

            self.ip = ipv4.get('ip')
            """
            The IP address associated with this object.

            :return: IPv4 address.
            :rtype: str
            """

            self.isp = ipv4.get('isp')
            """
            Internet Service Provider (ISP) for this object.

            :return: Name of ISP.
            :rtype: str
            """

            self.latitude = ipv4.get('latitude')
            """
            Latitude of ISP.

            :return: latitude
            :rtype: str
            """

            self.longitude = ipv4.get('longitude')
            """
            Longitude of ISP.

            :return: longitude
            :rtype: str
            """

            self.lookup_on = ipv4.get('lookupOn')
            """
            The timestamp when ASN information was retrieved about this.

            :return: Epoch timestamp.
            :rtype: int
            """

            self.metro_code = ipv4.get('metroCode')
            """
            Telephone metro code.

            :return: Telephone metro code.
            :rtype: int
            """

            self.organization = ipv4.get('organization')
            """
            The short form name of the organization responsible for this ASN.

            :return: The organization name.
            :rtype: str
            """

            self.postal_code = ipv4.get('postalCode')
            """
            Postal or zip code.

            :return: Postal or zip code.
            :rtype: str
            """

            self.subdivision_name = ipv4.get('subdivisionName')
            """
            State name.

            :return: State name.
            :rtype: str
            """

            self.subdivision_iso_code = ipv4.get('subdivisionIsoCode')
            """
            Two-letter state code.

            :return: State code.
            :rtype: str
            """

            self.time_zone = ipv4.get('timeZone')
            """
            Time zone.

            :return: Time zone.
            :rtype: str
            """

            self.user_type = ipv4.get('userType')
            """
            Type of user.

            :return: Type of user.
            :rtype: str
            """

    def __getattr__(self, item):
        return None


class URL(object):
    """

    """

    def __init__(self, url):
        """

        :param url:
        :return:
        """

        self.json = url
        """
        The raw JSON used to create the :class:`cofense_intelligence.core.brand_intelligence.URL` object.

        :return: String representation of this object
        :rtype: str
        """

        self.domain = url.get('domain')
        """
        The domain name part of the URI

        :return: URI domain
        :rtype: str
        """

        self.host = url.get('host')
        """
        The FQDN portion of the URI.

        :return: URI host.
        :rtype: str
        """

        self.path = url.get('path')
        """
        The portion of the URL following the domain name.

        :return: URI path.
        :rtype: str
        """

        self.protocol = url.get('protocol')
        """
        The TCP/IP protocol portion of a URI.

        :return: URI protocol.
        :rtype: str
        """

        self.query = url.get('query')
        """
        The portion of a URI after a '?' symbol.

        :return: URI query.
        :rtype: str
        """

        self.url = url.get('url')
        """
        The full URI.

        :return: URI.
        :rtype: str
        """

    def __getattr__(self, item):
            return None
