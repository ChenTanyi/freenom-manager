#!/usr/bin/env python3
import os
import re
import bs4
import logging
import requests
import urllib.parse

try:
    import lxml
    PARSER = 'lxml'
except:
    PARSER = 'html.parser'


class LoginError(Exception):
    pass


def ensure_login(func):

    def wrapper(self, *args):
        if not self._is_login:
            self.login(
                self._config.get('username', ''),
                self._config.get('password', ''))
            if not self._is_login:
                raise LoginError(
                    f'Please login first before perform {func.__name__}')
        return func(self, *args)

    return wrapper


class Freenom:

    def __init__(self, config = dict()):
        self._config = config
        self._is_login = False
        self._session = self._get_http_session(
            pool_size = config.get('pool_size', 10),
            retry = config.get('retry', 5),
        )
        self._previous_uri = 'https://my.freenom.com/clientarea.php'

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._session.__exit__(*args)

    def set_config(self, key, value):
        self._config[key] = value

    def login(self, username, password):
        r = self._session.post(
            'https://my.freenom.com/dologin.php',
            headers = {
                'Referer': self._previous_uri,
            },
            data = {
                'username': username,
                'password': password,
            },
        )
        self._previous_uri = r.url

        if 400 <= r.status_code < 600:
            logging.error(f'Login request failed with status {r.status_code}')
            logging.error(r.content)
        else:
            query = urllib.parse.urlparse(r.url).query
            if urllib.parse.parse_qs(query).get('incorrect') == 'true':
                logging.error('Login failed: incorrect details')
            else:
                self._is_login = True

    @ensure_login
    def list_domains_for_renew(self) -> list:
        # Domain List: name, status, remaining days, renewable message, renewable url
        uri = 'https://my.freenom.com/domains.php?a=renewals'
        r = self._session.get(
            uri,
            headers = {
                'Referer': self._previous_uri,
            },
        )
        r.raise_for_status()
        self._previous_uri = r.url

        html = bs4.BeautifulSoup(r.content, PARSER)
        domain_content = html('section', class_ = 'renewalContent')
        assert len(
            domain_content
        ) == 1, 'Domains page should only contain one renewalContent section'

        titles, rows, maxlen = self.parse_domain_list(domain_content,
                                                      'Renew This Domain', uri)
        logging.debug('Domain List:')
        self.logging_table(titles, rows, maxlen)
        return rows

    @ensure_login
    def renew_domain(self, uri: str, sess: requests.Session,
                     name: str = None) -> (bool, bytes):
        query = urllib.parse.urlparse(uri).query
        domain_id = urllib.parse.parse_qs(query).get('domain')
        if not domain_id:
            logging.error(f'Unable to get domain id from {uri}')
            return (False, None)

        domain_id = domain_id[0]
        logging.debug(f'renew domain id "{domain_id}"')

        # Just get the page, not sure it is needed indeed or not.
        r = sess.get(
            uri, headers = {
                'Referer': self._previous_uri,
            })
        self._previous_uri = r.url

        r = sess.post(
            'https://my.freenom.com/domains.php?submitrenewals=true',
            headers = {
                'Referer': self._previous_uri,
            },
            data = {
                'renewalid':
                    domain_id,
                f'renewalperiod[{domain_id}]':
                    self._config.get('period', '12M'),
                'paymentmethod':
                    'credit',
            })
        self._previous_uri = r.url
        logging.debug(f'renew response {r.status_code} {r.reason}')
        if 400 <= r.status_code < 600:
            return (False, r.content)
        else:
            return (True, r.content)

    @ensure_login
    def list_domains(self) -> list:
        # Domain List: name, registration date, expiry date, status, type, manage url
        uri = 'https://my.freenom.com/clientarea.php?action=domains'
        r = self._session.get(
            uri,
            headers = {
                'Referer': self._previous_uri,
            },
        )
        r.raise_for_status()
        self._previous_uri = r.url

        html = bs4.BeautifulSoup(r.content, PARSER)
        domain_content = html('section', class_ = 'domainContent')
        assert len(
            domain_content
        ) == 1, 'Domains page should only contain one domainContent section'

        titles, rows, maxlen = self.parse_domain_list(domain_content,
                                                      'Manage Domain', uri)
        logging.debug('Domain List:')
        self.logging_table(titles, rows, maxlen)
        return rows

    @ensure_login
    def manage_domain(
            self,
            uri: str,
            domain: str,
            sess: requests.Session,
            action: str,
            records: list = None,
    ):
        query = urllib.parse.urlparse(uri).query
        domain_id = urllib.parse.parse_qs(query).get('id')
        if not domain_id:
            logging.error(f'Unable to get domain id from {uri}')
            return

        domain_id: str = domain_id[0]
        logging.debug(f'manage domain id "{domain_id}"')

        # simulate browser
        # r = sess.get(
        #     uri,
        #     headers = {'Referer': self._previous_uri},
        # )
        # self._previous_uri = r.url

        uri = f'https://my.freenom.com/clientarea.php?managedns={domain}&domainid={domain_id}'
        # r = sess.get(
        #     uri,
        #     headers = {'Referer': self._previous_uri},
        # )
        self._previous_uri = uri

        params = {'dnsaction': action}
        if action == 'delete':
            params['managedns'] = domain
            params['domainid'] = domain_id
            for record in records:
                params['name'] = record['name']
                params['ttl'] = record['ttl']
                params['records'] = record['type']
                params['value'] = record['value']
                r = sess.get(
                    f'https://my.freenom.com/clientarea.php',
                    params = params,
                    headers = {'Referer': self._previous_uri},
                )
                r.raise_for_status()
                self._previous_uri = r.url
        elif action == 'add':
            for i in range(len(records)):
                params[f'addrecord[{i}][name]'] = records[i]['name']
                params[f'addrecord[{i}][type]'] = records[i]['type']
                params[f'addrecord[{i}][ttl]'] = records[i]['ttl']
                params[f'addrecord[{i}][value]'] = records[i]['value']

            r = sess.post(
                uri,
                data = params,
                headers = {'Referer': self._previous_uri},
            )
            r.raise_for_status()
            self._previous_uri = r.url
        # elif action == 'modify': # not modify currently
        else:
            logging.error(f'Unknown action {action} for domain {domain}')
            return

    @staticmethod
    def _get_http_session(pool_size = 10, retry = 5):
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_size, pool_size, retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    @staticmethod
    def trim(s: str) -> str:
        return re.sub(r'\s+', ' ', s).strip()

    @staticmethod
    def logging_table(titles, rows, length: int):
        format_func = lambda x: f'{x:<{length + 1}s}'

        logging.debug(' '.join(map(format_func, titles)))
        for row in rows:
            logging.debug(' '.join(map(format_func, row)))

    @staticmethod
    def parse_domain_list(domain_content, link_col, uri) -> (list, list, int):
        maxlen = 10
        titles = []
        rows = []

        for tr in domain_content[0]('tr'):
            if len(tr('th')) > 0:
                for th in tr('th'):
                    text = Freenom.trim(th.text)
                    if text:
                        titles.append(text)
            else:
                is_domain = True
                rows.append([])
                for td in tr('td'):
                    text = Freenom.trim(td.text)
                    if text == link_col:
                        assert len(
                            td('a')
                        ) == 1, f'More than one link found in {link_col} column'
                        rows[-1].append(
                            urllib.parse.urljoin(uri,
                                                 td('a')[0]['href']))
                    elif text:
                        rows[-1].append(text)
                        if is_domain:
                            maxlen = max(maxlen, len(text))
                            is_domain = False

        return titles, rows, maxlen
