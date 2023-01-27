import urllib.parse
from utils import conf
import re
import requests
import time

def filter_exists(filter):
    available_filters = {'region', 'ssl.cert.issuer.cn', 'country', 'telnet.option', 'telnet.dont', 'ssl.cert.extension', 'link', 'http.html', 'telnet.do', 'all', 'ntp.ip_count', 'asn', 'cloud.region', 'screenshot.label', 'shodan.module', 'ssh.type', 'hostname', 'http.favicon.hash', 'ssl.cipher.version', 'ssl.cipher.bits', 'http.headers_hash', 'ssl.cert.serial', 'ssl.cert.fingerprint', 'state', 'ntp.ip', 'http.securitytxt', 'cloud.provider', 'ssl.cert.pubkey.type', 'snmp.name', 'ssl.alpn', 'has_ssl', 'ssl.version', 'has_vuln', 'org', 'cpe', 'http.title', 'ssl.chain_count', 'cloud.service', 'ssl.jarm', 'postal', 'product', 'has_screenshot', 'ssl.cert.subject.cn', 'http.html_hash', 'ssl.cert.alg', 'http.status', 'http.component', 'vuln', 'ssl', 'net', 'ssl.cert.expired', 'ssl.ja3s', 'hash', 'bitcoin.ip_count', 'ssh.hassh', 'http.waf', 'device', 'snmp.location', 'http.robots_hash', 'ntp.port', 'city', 'version', 'ip', 'telnet.wont', 'has_ipv6', 'ssl.cipher.name', 'isp', 'os', 'telnet.will', 'screenshot.hash', 'snmp.contact', 'bitcoin.version', 'bitcoin.port', 'tag', 'http.component_category', 'ntp.more', 'geo', 'scan', 'bitcoin.ip', 'ssl.cert.pubkey.bits', 'port'}
    if filter in available_filters:
        return True
    else:
        return False

class Error(Exception):
    """Base class for other exceptions"""
    pass

class Shodan:
    
    # setting configuration fetched from conf.py file and validating it with properties mechanism
    def __init__(self):
        # opening queries.txt file and assigning it to query_list var
        with open('utils/queries.txt', 'r') as f:
            self.query_list = [line.strip() for line in f]
        self.cookie = conf.cookie
        self.user_agent = conf.user_agent
        self.ip_range = conf.ip_range
        self.interval = conf.interval
        self.additional_filters = conf.additional_filters
    
    @property
    def ip_range(self):
        return self._ip_range
    
    @ip_range.setter
    def ip_range(self, value):
        if re.match("^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$", value) or value == "":
            self._ip_range = value
        else:
            raise AttributeError(f"Provided ip syntax {value} doesn't look correct. Please check it out in conf.py file")

    @property
    def cookie(self):
        return self._cookie
    
    @cookie.setter
    def cookie(self, value):
        if re.match('^polito="[A-Za-z0-9]{64}!"$', value):
            self._cookie = value
        else:
            raise AttributeError(f"Provided cookie syntax {value} doesn't look correct. Please check it out in conf.py file")

    @property
    def interval(self):
        return self._interval

    @interval.setter
    def interval(self, value):
        try:
            self._interval = float(value)
        except ValueError:
            ValueError(f"Provided interval {value} has wrong type. Please check it out in conf.py file")
    
    @property
    def additional_filters(self):
        return self._additional_filters
    @additional_filters.setter
    def additional_filters(self,value):
        if type(value) is dict:
            for key in value.keys():
                if not filter_exists:
                    raise ValueError(f'Filter {key} does not exsist. Please check it out in conf.py file')
            self._additional_filters = value
        else:
            raise ValueError('Provided additional_filters dict: {value} has wrong type. Please check it out in conf.py file')

    @property
    def _headers_dict(self):
        return {
        "Cookie": self.cookie,
        "User-Agent": self.user_agent
        }

    def run(self):
        for query in self.query_list:
            current_query = self._prepare_query_url(query)
            page = requests.get(current_query, headers=self._headers_dict)
            if "Total Results" in page.text:
                print(f'{current_query}')
                with open('results.txt','a') as f:
                    f.write(f'{current_query}\n')
            elif "No results found" in page.text:
                pass
            elif "Please log in to use search filters" in page.text:
                raise Error(f"Your session is not properly validated. Check your cookie and user_agent properties on conf.py file")
            elif "Invalid search query" in page.text:
                print(f'Something is wrong with query: {current_query}. Consider deleting it')
            elif "Daily search usage limit reached" in page.text:
                raise Error(f"Daily search usage limit reached.\nLast query searched:{query}")
            else:
                print(page.text)
                raise Error(f"Some other error occured\nLast query searched: {query}")
                

                
        # make a program wait to prevent flooding shodan with requests
            time.sleep(self.interval)
    

    def _prepare_query_url(self, query):
        base_url = "https://www.shodan.io/search?query="
        # - ip address - additional filters
        if self.ip_range == "" and bool(self.additional_filters) == False:
            query = urllib.parse.quote_plus(f'{query}')
        # - ip address + additional filters
        elif self.ip_range != "" and bool(self.additional_filters) == True:
            additional_string = ""
            for key,value in self.additional_filters.items():
                additional_string += f' {key}:{value}'
            query = urllib.parse.quote_plus(f'{query}{additional_string}')
        # + ip address - additional filters
        elif bool(self.additional_filters) == False:
            query = urllib.parse.quote_plus(f'{query} ip:{self.ip_range}')
        # + ip address + additional filters
        else:
            additional_string = ""
            for key,value in self.additional_filters.items():
                additional_string += f' {key}:{value}'
            query = urllib.parse.quote_plus(f'{query} {self.ip_range}{additional_string}')

        return base_url+query


