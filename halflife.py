#!/usr/bin/env python3

import datetime
import json
import logging
import subprocess
from itertools import groupby
import traceback
import re
from platform import node

import requests

from msapi import MetasmokeApi, MetasmokeApiError, DisabledError
######## TODO: maybe replace with actioncable-zwei
# https://github.com/tobiasfeistmantl/python-actioncable-zwei
from actioncable import ActionCableClient


class FetchError (Exception):
    pass


class FetchTooLargeError(FetchError):
    pass


class FetchTimeoutError(FetchError):
    pass


class HalflifeClient (ActionCableClient):
    def location(self, filename="location.txt"):
        """
        Read location from location.txt, else platform.node()
        """
        try:
            with open(filename) as locationfile:
                return locationfile.read().strip()
        except FileNotFoundError:
            return node()

    def init_hook (self):
        self.flagged = set()
        self.checker = Halflife(key=self.key)
        ######## TODO: should perhaps be level=info
        from os import uname
        logging.warning('[Halflife](https://github.com/Charcoal-SE/halflife) '
            '%s running on %s started %s UTC',
                subprocess.run(['git', 'describe', '--always'],
                    stdout=subprocess.PIPE,
                    universal_newlines=True).stdout.strip(),
            self.location(), datetime.datetime.utcnow())

    '''
    ######## TODO: remove dead code
    def on_flag (self, ws, arg):
        logging.info('flag_log %s', arg['message'])
        link = arg['message']['flag_log']['post']['link']
        if link not in self.flagged:
            self.checker.check(arg['message']['flag_log']['post'])
            self.flagged.update([link])
        else:
            logging.info('Already flagged %s, not checking again', link)

    def on_not_flagged (self, ws, arg):
        logging.info('not_flagged %s', arg['message'])
        self.checker.check(arg['message']['not_flagged']['post'])
    '''
    def on_event_post_create (self, ws, arg):
        logging.info('event:Post:create %s', arg['message'])
        if 'object' in arg['message']:
            link = arg['message']['object']['link']
            if link not in self.flagged:
                try:
                    self.checker.check(arg['message']['object'])
                    self.flagged.update([link])
                except DisabledError as e:
                    logging.warning('Untrapped DisabledError %r', e)
                except Exception as e:
                    traceback.print_exc()

            else:
                logging.info('Already flagged %s, not checking again', link)
        else:
            logging.warning('No "object" in %s', arg['message'])


class Halflife ():
    def __init__ (self, key):
        self.key = key
        self.previous_id = None

        self.msapi = MetasmokeApi(self.key)

        self.domain_whitelist = [
            'i.stack.imgur.com',
            'stackoverflow.com',
            'stackexchange.com',
            'superuser.com',
            'serverfault.com',
            'askubuntu.com',
            'mathoverflow.net',
            # common FPs
            'example.com',
            'localhost',
            '127.0.0.1',
            'advancedcustomfields.com',
            'ag-grid.com',
            'amazon.ca',
            'amazon.com',
            'amazon.de',
            'amzn.to',
            'android-x86.org',
            'android.com',
            'angular.io',
            'apache.org',
            'apple.com',
            'appuals.com',
            'azurewebsites.net',
            'behance.net',
            'cisco.com',
            'codebeautify.com',
            'codechef.com',
            'codepen.io',
            'codesandbox.io',
            'dafont.com',
            'devart.com',
            'dictionary.com',
            'docker.com',
            'doi.org',
            'dropbox.com',
            'drupal.org',
            'ergoemacs.org',
            'facebook.com',
            'fritz.ai',
            'geeksforgeeks.org',
            'getbootstrap.com',
            'git-scm.com',
            'github.com',
            'github.io',
            'google.com',
            'google.ie',
            'googleapis.com',
            'guru99.com',
            'gyazo.com',
            'hastebin.com',
            'ibb.co',
            'icloud.com',
            'ieee.org',
            'imgur.com',
            'instagram.com',
            'ionicframework.com',
            'jsfiddle.net',
            'json.org',
            'jsonworld.com',
            'kaggle.com',
            'kite.com',
            'learncpp.com',
            'maketecheasier.com',
            # 'marketwatch.com',  # do not whitelist; prevents _fetch()
            'matplotlib.org',
            'medium.com',
            'merriam-webster.com',
            'microsoft.com',
            'morningstar.com',
            'mozilla.org',
            'mysql.com',
            'nesbot.com',
            'nih.gov',
            'npmjs.com',
            'oracle.com',
            'pastebin.com',
            'paypal.com',
            'prnt.sc',
            'prntscr.com',
            'pypa.io',
            'pypi.org',
            'qiita.com',
            'reactjs.org',
            'reddit.com',
            'regex101.com',
            'robjhyndman.com',
            'rudrastyh.com',
            'scikit-learn.org',
            'sourceforge.net',
            'spacy.io',
            'spring.io',
            'st.com',
            'stackblitz.com',
            'streamable.com',
            'swig.org',
            't.me',
            'tcl.tk',
            'tensorflow.org',
            'torproject.org',
            'towardsdatascience.com',
            'tutorialspoint.com',
            'twitter.com',
            'ubuntu.com',
            'ui.vision',
            'visualstudio.com',
            'w3schools.com',
            'wikipedia.org',
            'xda-developers.com',
            'youtu.be',
            'youtube.com',
            ]
        self.redirectors = [
            '0i.is',
            'bit.ly',
            'clck.ru',
            # *.hop.clickbank.net,
            'clicky.com',
            'cutt.ly',
            'firsturl.de',
            'goo.gl',
            'href.li',
            'is.gd',
            'lnkd.in',
            'pin.it',
            'qr.ae',
            'rb.gy',
            'rebrand.ly',
            'shorturl.at',
            'surl.li',
            't.co',
            't.ly',
            'tinyurl.com',
            ]
        ######## TODO: load a pickle?
        self.host_lookup_cache = dict()
        self.url_visit_cache = dict()
        self.ascache = dict()

        self.autoflagging_threshold = 280
        self.blacklist_thres = 30  # 30 hits or more means blacklist
        self.auto_age_thres = 180  # 180 days == 6 months
        self.auto_thres = 20       # 20 hits in 180 days means blacklist

    def check (self, message):
        def strip_code_blocks (post):
            frags = post.split('<pre><code>')
            body = [frags[0]]
            for frag in frags[1:]:
                body.append(frag.split('</code></pre>')[1])
            return '\n'.join(body)

        def find_phones (post):
            """
            Crude phone number candidate extraction.
            """
            phone_min = 9
            phone_max = 14
            phones = []
            for alpha, candidate in groupby(post,
                    key=lambda x: x.isalpha() or '/' == x):
                if not alpha:
                    candidate = ''.join(ch for ch in candidate if ch.isdigit())
                    if len(candidate)-2 > len(candidate.rstrip('0')):
                        # probably a big number with many trailing zeros
                        continue
                    if phone_min <= len(candidate) <= phone_max:
                        phones.append(candidate)
            return phones

        def parse_why (post):
            """
            Attempt to parse the human-readable "why": data from
            a single string into a somewhat structured representation.

            This still lacks the precise reason (the reasons are
            enumerated separately).
            """
            why = post['why']
            items = []
            matches = {}
            for line in why.split('\n'):
                items.extend(line.split(', '))
            for i in range(len(items)):
                if items[i] == '':
                    continue

                # ######## FIXME: quick and dirty, put this in a separate dict?
                if 'com.appmaster.akash' in items[i]:
                    logging.warn(
                        'ping @tripleee @MartijnPieters com.appmaster.akash')

                if not items[i].startswith(
                        ('Body -', 'Title -', 'Username -',
                         'Position ', 'Positions ')):
                    offset=1
                    while items[i-offset] == '':
                        offset += 1
                    items[i-offset] += ', ' + items[i]
                    items[i] = ''
            for item in items:
                parts = item.split(': ', 1)
                if len(parts) == 2:
                    if parts[1] not in matches:
                        matches[parts[1]] = [item]
                    else:
                        matches[parts[1]].append(item)
            return matches

        def host_report(url_result, url, post_id):
            """
            Summarize results from url_check(url)
            """
            if 'dns_check' not in url_result or \
                    'host' not in url_result['dns_check']:
                logging.debug('%s: no dns_check result for `%s`', post_id, url)
            else:
                host = url_result['dns_check']['host']
                if url_result['dns_check'][':cached']:
                    logging.info('%s: %s: cached DNS result, '
                        'not reporting again', post_id, host)
                else:
                    logging.warning('%s: %s: ns %s',
                        post_id, host, url_result['dns_check']['ns'])
                    for ip in set(url_result['dns_check']['a']):
                        if ip in set(url_result['dns_check']['rdns']):
                            rdns = url_result['dns_check']['rdns'][ip]
                            if rdns == None:
                                rdns = ''
                            if len(rdns) == 1:
                                rdns = rdns[0]
                        else:
                            rdns = ''
                        logging.warning('%s: %s: ip %s (%s)',
                            post_id, host, ip, rdns)

                        if 'asn' in url_result['dns_check']:
                            for asn in url_result['dns_check']['asn']:
                                logging.warning('%s: %s: ip %s AS %s (%s/%s)',
                                    post_id, host, ip,
                                        asn[0], asn[1]['name'], asn[1]['cc'])

            if 'tail_check' not in url_result:
                logging.debug('%s: no tail from URL `%s`', post_id, url)
            else:
                for tail, result in url_result['tail_check'].items():
                    if not result:
                        tail = tail.lower()
                        if tail in message[':why']:
                            result = 'matched (watched or blacklisted)'
                        else:
                            for suffix in ['-be', '-fr', '-us',
                                '-south-africa', '-supplement', '-cream',
                                '-serum', '-garcinia', '-force', '-skin',
                                '-pro', '-oil', '-male-enhancement',
                                '-anti-aging']:
                                if tail.endswith(suffix):
                                    tail = tail[:-len(suffix)]
                            for why in message[':why']:
                                if len(why) > 2*len(tail) or \
                                        any([x in why
                                            for x in ['link at end']]):
                                    pass
                                elif tail == why.lower():
                                    result = 'matched in ' + \
                                        '; '.join(message[':why'][why])
                                    break
                                elif tail in why.lower().replace(url, ''):
                                    if result:
                                        result += '; '
                                    else:
                                        result = ''
                                    result += 'matched in ' + why
                    '''
                    if not result or result == 'watched':
                        tail_re = tail.replace('-', '[^A-Za-z0-9_]?')
                        try:
                            tail_query = self.tp_query(tail_re)
                            logging.warning('%s: regex %s search: %s/%s hits',
                                post_id, tail.replace('-', r'\W?'),
                                    tail_query['tp_count'],
                                        len(tail_query['hits']))
                        except (MetasmokeApiError, DisabledError) as err:
                            logging.error('Could not perform query for %s (%s)',
                                tail_re, err)
                    '''
                    if not result:
                        result = 'not blacklisted or watched'
                    logging.warning(
                        '%s: URL tail %s is %s', post_id, tail, result)

            if 'metasmoke' not in url_result:
                logging.debug('%s: no metasmoke result for `%s`', post_id, url)
            else:
                hits = url_result['metasmoke']
                count = len(hits['items'])
                if count == 0:
                    logging.warning('%s: %s: No metasmoke hits', post_id, host)
                elif count == 1:
                    logging.warning('%s: %s: first hit', post_id, host)
                else:
                    logging.warning('%s: %s: %s/%s over %s', post_id, host,
                        hits[':feedback']['tp'], hits[':feedback'][':all'],
                            hits[':timespan'])
                    if 'whois' in url_result:
                        logging.debug('whois %r', url_result['whois'])
                    else:
                        logging.debug('no whois in %r', url_result.keys())

        if not self.msapi.get_post_metainformation(message):
            logging.warning('No MS metainformation for %s', message)
            return None

        weight = message[':weight']
        post_id = message['id']

        if self.previous_id != None:
            if int(post_id) == self.previous_id:
                logging.warning(
                    '%s already seen; not processing again', post_id)
                return
            # else
            if int(post_id) != self.previous_id+1:
                logging.warning('[%s] is not %s+1', post_id, self.previous_id)
        self.previous_id = int(post_id)

        logging.warning('[%s](https://metasmoke.erwaysoftware.com/post/%s):'
            ' Check post [https:%s](https:%s) (%s)', post_id, post_id,
                message[':meta']['link'], message[':meta']['link'], weight)
        logging.debug('url: %s', message['link'])
        logging.debug('title: %s', message['title'])
        logging.debug('body: %s', message['body'])
        logging.debug('username: %s', message['username'])
        message[':why'] = parse_why(message)

        ######## TODO: don't hardcode limit
        if weight < 280 and any([x['reason_name'].startswith('Blacklisted ')
                for x in message[':reasons']]):
            logging.error(
                '%s: Blacklisted contents but post still below auto', post_id)

        cleaned_body = strip_code_blocks(message['body'])
        logging.info('Body with code blocks stripped is %r', cleaned_body)

        phones = set(find_phones(cleaned_body))
        phones = phones.union(set(find_phones(message['title'])))
        logging.info('Phone number candidates: %r', phones)
        for phone in phones:
            logging.warning(
                '%s: Extracted possible phone number %s', post_id, phone)
        '''
        phone_result = self.check_phones(phones)
        for phone in phone_result:
            logging.warning(
                '%s: Extracted possible phone number %s', post_id, phone=phone)
            if 'search' not in phone_result[phone]:
                logging.debug('%s: no search result for %s', post_id, phone)
            else:
                logging.warning('%s: %s search %s/%s over %s',
                    post_id, phone, phone_result[phone]['search']['tp_count'],
                        len(phone_result[phone]['search']['hits']),
                            phone_result[phone]['search']['timespan'])
        '''
        urls = set()
        if 'http://' in message['title'] or 'https://' in message['title']:
            urls.update(self.pick_urls(message['title']))
        elif 'www.' in message['title']:
            urls.update(self.pick_urls(message['title'], www=True))
        if '<a href="' in cleaned_body:
            urls.update([frag.split('"')[0]
                for frag in cleaned_body.split('<a href="')[1:]])
        elif 'http://' in cleaned_body or 'https://' in cleaned_body:
            urls.update(self.pick_urls(cleaned_body))
        elif 'www.' in cleaned_body:
            urls.update(self.pick_urls(cleaned_body, www=True))

        logging.info('urls are %r', urls)
        logging.info('Metasmoke found %r', message[':domains'])

        if len(urls) > 0:

            url_result = self.check_urls(urls)

            # ######## FIXME: this should probably be in msapi.py
            message[':domain_id_map'] = dict()
            message[':domain_id_whois'] = dict()
            for domain in message[':domains']:
                message[':domain_id_map'][domain['domain']] = domain['id']
                message[':domain_id_whois'][domain['id']] = domain['whois']

            for host in url_result[':metasmoke_domain_queue']:
                if host in message[':domain_id_map']:
                    domain_id = message[':domain_id_map'][host]
                    try:
                        host_result = self.msapi.domain_query(domain_id)
                    except MetasmokeApiError as err:
                        logging.error(
                            'Could not perform domain query for %s (%s)',
                                host, err)
                        continue
                    for url in url_result[':metasmoke_domain_queue'][host]:
                        url_result[url]['metasmoke'] = host_result
                        url_result[url]['whois'] = \
                          message[':domain_id_whois'][domain_id]
                else:
                    logging.warning(
                        'Domain %s not extracted by metasmoke', host)

            for url in url_result:

                if url.startswith(':metasmoke'):
                    logging.debug('Skipping pseudo-URL %s: %r',
                        url, url_result[url])
                    continue

                logging.warning('%s: Extracted URL `%s`', post_id, url)
                if 'domain_check' not in url_result[url]:
                    logging.debug(
                        '%s: No domain_check result for `%s`', post_id, url)
                    ######## TODO: maybe check :why here too?
                else:
                    for host in url_result[url]['domain_check']:
                        what = url_result[url]['domain_check'][host]
                        if not what:
                            if host in message[':why']:
                                logging.warning('%s: %s matched: %s',
                                    post_id, host,
                                        '; '.join(message[':why'][host]))
                            else:
                                logging.error(
                                    '%s: %s is not blacklisted or watched',
                                        post_id, host)
                        else:
                            logging.warning(
                                '%s: %s is %s', post_id, host, what)

                        if what and 'blacklisted' in what and (
                            'whois' not in url_result[url] or
                                url_result[url]['whois'] is None):
                            # logging.warning(
                            #    '%s: no whois for blacklisted domain %s'
                            #         post_id, host)
                            logging.info(
                                'url_result[%s] is %r', url, url_result[url])

                if 'request_check' in url_result[url]:
                    status = url_result[url]['request_check'].status_code
                    if status != 200:
                        logging.warning(
                            '%s: HTTP status %s for `%s`', post_id, status, url)

                if 'go-url' in url_result[url]:
                    for go_url in url_result[url]['go-url']:
                        dest = url_result[url]['go-url'][go_url]
                        logging.warning('%s: Wordpress promotion URL `%s` '
                            'redirects to `%s`', post_id, go_url, dest)
                        if dest not in url_result and \
                                dest + '/' not in url_result:
                            url_check = self.check_urls([dest], recurse=False)
                            host_report(url_check[dest], dest, post_id)

                if 'mw-url' in url_result[url]:
                    for mw_url in url_result[url]['mw-url']:
                        dest = url_result[url]['mw-url'][mw_url]
                        logging.warning('%s: MarketWatch URL `%s` '
                            'links to `%s`', post_id, url, dest)
                        if dest not in url_result and \
                                dest + '/' not in url_result:
                            url_check = self.check_urls([dest], recurse=False)
                            host_report(url_check[dest], dest, post_id)

                host_report(url_result[url], url, post_id)

    '''
    def check_phones(self, phones):
        """
        Check a list of ostensible phone numbers.
        """
        result = dict()
        for phone in phones:
            result[phone] = {}
            try:
                result[phone]['search'] = self.phone_query(phone)
            except MetasmokeApiError as err:
                logging.error('Could not perform phone query for %s (%s)',
                    phone, err)
        return result
    '''

    def pick_urls(self, string, www=False):
        """
        Very quick and dirty heuristic URL extractor.

        With www=True, look for bare host names without a http:// or https://
        protocol specifier using an even more crude regex.
        """
        if www:
            return re.findall(r'(\w+(?:\.\w+)+)(?=\W|$)', string)
        # else:
        urls = []
        for frag in string.split('http')[1:]:
            logging.info('examining fragment %s', frag)
            if frag.startswith('s://') or frag.startswith('://'):
                candidate = 'http' + frag.split()[0]
                candidate = candidate.split('">')[0]
                candidate = candidate.rstrip('">')
                if '%20' in candidate:
                    continue
                elif candidate.startswith('http://http') and \
                    not candidate.startswith(
                        ('http://http.', 'http://https.')):
                    candidate = candidate[7:]
                elif candidate.startswith('https://http') and \
                    not candidate.startswith(
                        ('https://http.', 'https://https.')):
                    candidate = candidate[8:]
                urls.append(candidate)
        return urls

    def check_urls(self, urls, recurse=True):
        '''
        Check a list of URLs.

        With recurse=False, don't attempt to fetch.
        '''
        def _requests_get_timeout(url, timeout=60, maxsize=0):
            """
            Like requests.get() but use chunking to implement timeout
            and max size for fetch.

            maxsize is optional; set to 0 (default) to not have a maximum
            size for the download.
            """
            # https://stackoverflow.com/a/22347526
            response = requests.get(url, timeout=timeout,
                # Emulate Firefox, copy/paste from my computer
                headers={
                    'User-Agent': 'Mozilla/5.0 (Macintosh; '
                        'Intel Mac OS X 10.12; rv:58.0) '
                        'Gecko/20100101 Firefox/58.0',
                    'Accept': 'text/html,application/xhtml+xml,'
                        'application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    ######## TODO: replace this with something less static?
                    'Cookie': 'remember_user_token=WyJiYXNlNjQgaW5mb3'
                        'JtYXRpb24iXSxbImxvdHMgb2YgaXQiXQo=',
                    'Connection': 'keep-alive', # is this safe?
                    'Upgrade-Insecure-Requests': '1',
                    })
            response.raise_for_status()

            logging.info(
                'Content-Length: %s from URL %s',
                response.headers.get('Content-Length'), url)

            size = 0
            starttime = datetime.datetime.utcnow()
            maxtime = starttime + datetime.timedelta(seconds=timeout)

            chunksize = 1024
            chunks = []
            for chunk in response.iter_content(chunksize):
                size += len(chunk)
                chunks.append(chunk)

                if size >= maxsize:
                    logging.warning(
                        'Max size %i reached or exceeded for URL %s;'
                        ' returning first %i bytes' % (
                            maxsize, url, size))
                    break

                if datetime.datetime.utcnow() > maxtime:
                    logging.warning(
                        'Max time %i seconds exceeded for URL %s;'
                        ' returning first %i bytes' % (
                            maxtime, url, size))
                    break

            return response

        def _fetch (url):
            """
            Use requests to fetch the URL, pretend to be a browser.
            """
            if url in self.url_visit_cache:
                ######## TODO: make url_visit_cache objects opaque
                logging.warning(
                    'Visited URL at %s; returning cached result for `%s`',
                        self.url_visit_cache[url][0], url)
                return self.url_visit_cache[url][1]
            try:
                response = _requests_get_timeout(
                    url, timeout=20, maxsize=1048576)
                logging.info('Status %s for URL `%s`',
                    response.status_code, url)
                logging.debug(
                    'Fetched (%i bytes) %r', len(response.text), response.text)
                ######## TODO: make url_visit_cache objects opaque
                self.url_visit_cache[url] = (
                    datetime.datetime.utcnow(), response)
                return response
            except Exception as exc:
                logging.warning('Failed to fetch URL `%s` (%r)', url, exc)
                raise FetchError(str(exc))

        seen = set()
        result = {':metasmoke_domain_queue': dict()}
        for url in urls:
            result[url] = {}
            parts = url.split('/', maxsplit=3)
            if len(parts) == 1:
                parts = ('', '', url, '')
            elif len(parts) < 4:
                parts.extend([None] * (4-len(parts)))
            proto, _, host, tail = parts

            if host is None or '%20' in proto or '%20' in host \
                    or '%3' in proto or '%3' in host:
                continue
            if host.startswith('www.'):
                host = host[4:]
            if host not in seen:
                seen.update([host])
                host_re = host.replace('.', r'\.') + '$'
                whitelisted = False
                redirector = False
                for white in self.domain_whitelist:
                    if host == white or host.endswith('.' + white):
                        whitelisted = True
                        break
                if not whitelisted:
                    for redir in self.redirectors:
                        if host == redir or host.endswith('.' + redir):
                            redirector = True
                            break
                if whitelisted:
                    result[url]['domain_check'] = {host: 'whitelisted'}
                    continue
                elif redirector:
                    result[url]['domain_check'] = {host: 'redirector'}
                elif self.listed('^' + host_re, 'blacklisted_websites.txt'):
                    result[url]['domain_check'] = {host: 'blacklisted'}
                else:
                    if self.listed('\t' + host_re, 'watched_keywords.txt'):
                        result[url]['domain_check'] = {host: 'watched'}
                    else:
                        result[url]['domain_check'] = {host: None}
                    if host in result[':metasmoke_domain_queue']:
                        result[':metasmoke_domain_queue'][host].add(url)
                    else:
                        result[':metasmoke_domain_queue'][host] = set([url])

            if not redirector and not whitelisted:
                if tail:
                    tailresult = None
                    tailcopy = tail
                    while tailcopy.startswith('/'):
                        tailcopy = tailcopy[1:]
                    while tailcopy.endswith('/'):
                        tailcopy = tailcopy[:-1]
                    if tail and '/' not in tailcopy:
                        # FIXME: poor code duplication of bad_pattern_in_url()
                        for suffix in ['-reviews', '-review', '-support',
                                '-and-scam', '-or-scam', '-canada']:
                            if tailcopy.lower().endswith(suffix):
                                tailcopy = tailcopy[:-(len(suffix))]
                        tail_regex = tailcopy.replace('-', r'\W?') + '$'
                        if self.listed('^' + tail_regex,
                                'bad_keywords.txt', escape=False):
                            tailresult = 'blacklisted'
                        elif self.listed('\t' + tail_regex,
                                'watched_keywords.txt', escape=False):
                            tailresult = 'watched'
                        result[url]['tail_check'] = {tailcopy: tailresult}

                result[url]['dns_check'] = self.dns(host)

            if not whitelisted:
                try:
                    if '/' not in url:
                        logging.debug('Adding http:// in front of bare %s', url)
                        actual_url = 'http://' + url
                    else:
                        actual_url = url

                    if recurse:
                        response = _fetch(actual_url)

                        result[url]['request_check'] = response

                        if response.status_code == 200:
                            if response.url.rstrip('/') != url.rstrip('/'):
                                logging.warning('`%s` redirects to `%s`',
                                    url, response.url)
                            if '<meta name="generator" content="WordPress' \
                                    in response.text:
                                logging.debug('Found WordPress <meta> tag')
                                srcset_urls = set()
                                for line in response.text.split('\n'):
                                    if ' srcset="' in line and '><img ' in line:
                                        for surl in self.pick_urls(line):
                                            if surl.endswith('.jpg') or \
                                                    '.jpg?' in surl:
                                                logging.debug(
                                                    'Skip JPG URL %s', surl)
                                                continue
                                            if surl.endswith('.png') or \
                                                    '.png?' in surl:
                                                logging.debug(
                                                    'Skip PNG URL %s', surl)
                                                continue
                                            srcset_urls.add(surl)
                                logging.debug('srcset= URLS: %r', srcset_urls)
                                if len(srcset_urls) > 5:
                                    logging.info(
                                        'List of URLs too long, skipping')
                                    srcset_urls = []
                                if 'go-url' not in result[url]:
                                    result[url]['go-url'] = dict()
                                for go_url in srcset_urls:
                                    try:
                                        go_response = _fetch(go_url)
                                    except FetchError as exc:
                                        logging.warning(
                                            'Failed to fetch %s (%r)',
                                                go_url, exc)
                                        continue
                                    if go_response.url == go_url:
                                        logging.debug(
                                            'No redirect `%s`', go_url)
                                    else:
                                        result[url]['go-url'][
                                            go_url] = go_response.url
                                        '''
                                        result.update(self.check_urls(
                                            [go_response.url], recurse=False))
                                        '''

                            # ######## FIXME: fugly near-duplication of code
                            elif url.startswith('https://www.marketwatch.com/'
                                    'press-release/'):
                                logging.debug('Looking for "article-body" in '
                                    'retrieved Marketwatch page')
                                if '<div id="article-body"' in response.text:
                                    logging.debug('Found "article-body" div')
                                    dest_urls = set()
                                    snip = response.text.split(
                                        '<div id="article-body"')[1].split(
                                            '\n', 1)[1].split('<div ')[0]
                                    for line in snip.split('\n'):
                                        for link in line.split('<a href="')[1:]:
                                            link = link.split('"', 1)[0]
                                            dest_urls.add(link)
                                    logging.debug(
                                        'Destination URLs: %r', dest_urls)
                                    if 'mw-url' not in result[url]:
                                        result[url]['mw-url'] = dict()
                                    for mw_url in dest_urls:
                                        try:
                                            mw_response = _fetch(mw_url)
                                        except FetchError as exc:
                                            logging.warning(
                                                'Failed to fetch `%s` (%r)',
                                                mw_url, exc)
                                            continue
                                        result[url]['mw-url'][
                                            mw_url] = mw_response.url

                            else:
                                logging.debug('Not a WordPress page apparently;'
                                    ' not MarketWatch')


                except FetchError as exc:
                    logging.warning('Failed to fetch `%s` (%r)', url, exc)

        return result

    def listed(self, host_re, listfile, escape=True):
        ######## TODO: maybe replace with a metasmoke query
        ######## FIXME: if the listed regex is broader, this will miss it
        if escape:
            host_re = host_re.replace('\\', '\\\\')
        try:
            logging.debug('running %r', ['grep', '-qis', host_re, listfile])
            subprocess.run(['grep', '-qis', host_re, listfile], check=True)
            logging.debug('returning True')
            return True
        except subprocess.CalledProcessError:
            logging.debug('returning False')
            return False

    '''
    def word_query (self, regex):
        """
        Perform a regex query with word boundaries on both sides of the regex.
        """
        word_re = r'(^|[^A-Za-z0-9_]){0}([^A-Za-z0-9_]|$)'.format(regex)
        ######## FIXME: 'per_page': 100; add a filter
        query = self.api_query(
            'posts/search/regex?query={re}'.format(re=word_re))
        if 'items' not in query:
            raise MetasmokeApiError('No "items" in {0!r}'.format(query))
        return query

    def tp_query (self, regex):
        """
        Return hits, timespan, tp_count, below auto for a word-bounded regex.
        """
        raise DisabledError('sorry, regex query is disabled')
        hits_query = self.word_query(regex)
        hits = hits_query['items']
        tp = [x for x in hits
            if x['is_tp'] and not x['is_naa'] and not x['is_fp']]
        # Don't check weights if we can't blacklist anything anyway
        # or if the blacklisting criteria are triggered regardless of weights
        weight = None
        below_auto = None
        if len(hits) > 1 and len(tp) < self.blacklist_thres:
            hits_details = self.api_query('posts/{ids}'.format(
                ids=';'.join([str(x['id']) for x in hits])))
            weight = dict()
            below_auto = 0
            for hit in hits_details['items']:
                weight[hit['id']] = hit['reason_weight']
        post_date_max = None
        post_date_min = None
        for hit in hits:
            self.get_post_metainformation(
                # Filter picks
                # [X] posts.id
                # [X] posts.title
                # [X] posts.body
                # [X] posts.link
                # [X] posts.post_creation_date
                # [X] posts.created_at
                # [ ] posts.updated_at
                # [X] posts.site_id
                # [ ] posts.user_link
                # [ ] posts.username
                # [X] posts.why
                # [ ] posts.user_reputation
                # [X] posts.score
                # [ ] posts.upvote_count
                # [ ] posts.downvote_count
                # [ ] posts.stack_exchange_user_id
                # [X] posts.is_tp
                # [X] posts.is_fp
                # [X] posts.is_naa
                # [ ] posts.revision_count
                # [X] posts.deleted_at
                # -v-v-v-v-v v2 only -v-v-v-v-v-v-
                # [ ] posts.smoke_detector_id
                # [ ] posts.autoflagged
                #hit, filter='AAAAAAAAAPSjgAAAAAABAA==')
                hit, filter='')
            post_date = datetime.datetime.strptime(
                hit[':meta']['created_at'][0:19], '%Y-%m-%dT%H:%M:%S')
            if post_date_max is None or post_date > post_date_max:
                post_date_max = post_date
            if post_date_min is None or post_date < post_date_min:
                post_date_min = post_date
            if weight:
                wt = weight[hit['id']]
                hit['weight'] = wt
                if wt < self.autoflagging_threshold and \
                        not hit['is_naa'] and not hit['is_fp']:
                    ######## TODO: don't log if it's all FP; include verdicts
                    logging.warning('Post %s below auto (%s) %s ago',
                            hit['id'], wt, datetime.datetime.now()-post_date)
                    below_auto += 1
            else:
                logging.info('%s results; not getting weights', len(hits))
        ######## TODO: properly encapsulate result in a separate object
        if post_date_min and post_date_max:
            timespan = post_date_max - post_date_min
        else:
            timespan = datetime.timedelta()
        return {
            'hits': hits,
            'timespan': timespan,
            'tp_count': len(tp),
            'below_auto': below_auto
            }

    def phone_query (self, phone):
        regex = r'(^|[^A-Za-z0-9_]){0}([^A-Za-z0-9_]|$)'.format(
            r'[^A-Za-z0-9_]*'.join(phone))
        return self.tp_query(regex)
    '''

    def dns (self, host):
        ######## TODO: maybe replace with dnspython
        def _dig (query, host):
            q = subprocess.run(['dig', '+short', '-t', query, host],
                check=False, stdout=subprocess.PIPE, universal_newlines=True)
            if q.stdout == '\n':
                logging.info('_dig(%r, %r) = []', query, host)
                return []
            result = q.stdout.rstrip('\n').split('\n')
            logging.info('_dig(%r, %r) = %r', query, host, result)
            return result

        def isip (addr):
            for ch in ['.'] + [str(i) for i in range(0,10)]:
                addr = addr.replace(ch, '')
            return addr == ''

        if host in self.host_lookup_cache:
            self.host_lookup_cache[host][':cached'] = True
            return self.host_lookup_cache[host]

        result = {'host': host, 'ns': _dig('ns', host), ':cached': False}

        if any([x.endswith('root-servers.net.') for x in result['ns']]):
            logging.warning('NS contains root-servers.net.; abandoning')
            return result

        ######## TODO: soa, extract TTL

        ip = _dig('a', host)
        result['a'] = ip
        result['rdns'] = dict()
        for addr in ip:
            if addr == '':
                continue
            cleanaddr = addr.rstrip('.')
            if isip(cleanaddr):
                raddr = '.'.join(reversed(cleanaddr.split('.')))
                rdns = _dig('cname', raddr + '.in-addr.arpa.')
                if rdns == ['']:
                    rdns = _dig('ptr', raddr + '.in-addr.arpa.')
                if rdns == ['']:
                    rdns = None
                result['rdns'][addr] = rdns

                asr = _dig('txt', raddr + '.origin.asn.cymru.com.')
                if asr == ['']:
                    asr = None
                elif ' | ' in asr[0]:
                    asn, prefix, cc, registry, alloc_date = \
                        asr[0].strip('"').split(' | ')
                    if asn not in self.ascache:
                        asresult = []
                        for _as in asn.split(' '):
                            asquery = 'AS' + _as + '.asn.cymru.com'
                            asq = _dig('txt', asquery)
                            if asq == ['']:
                                logging.warning(
                                    'AS query for %s failed', asquery)
                            else:
                                # asn, cc, registry, alloc_date, asname
                                asfield = asq[0].strip('"').split(' | ')
                                self.ascache[_as] = {
                                    'cc': asfield[1],
                                    'registry': asfield[2],
                                    'alloc_date': asfield[3],
                                    'name': asfield[4],
                                }
                            asresult.append((_as, self.ascache[_as]))
                        ######## FIXME: fugly
                        result['asn'] = asresult

        ip6 = _dig('aaaa', host)
        result['aaaa'] = ip6
        ######## TODO: reverse DNS for IPv6

        self.host_lookup_cache[host] = result
        return result


def main():
    from sys import argv
    loglevel = logging.WARNING
    if '-d' in argv or '--debug' in argv:
        loglevel = logging.DEBUG
    logging.basicConfig(
        level=loglevel, format='%(module)s:%(asctime)s:%(message)s')
    with open('halflife.conf', 'r') as conffile:
        conf = json.loads(conffile.read())
    HalflifeClient(key=conf['metasmoke-key'])


if __name__ == '__main__':
    main()
