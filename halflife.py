#!/usr/bin/env python3

import datetime
import json
import logging
import subprocess

import requests
import websocket


######## TODO: maybe replace with actioncable-zwei
# https://github.com/tobiasfeistmantl/python-actioncable-zwei
class ActionCableClient ():
    def __init__(
            self,
            key=None,
            ws_url='wss://metasmoke.erwaysoftware.com/cable',
            enable_trace=False):
        self.key = key
        if enable_trace:
            websocket.enableTrace(True)
        self.ws = websocket.WebSocketApp(
            ws_url,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close)
        self.ws.on_open = self.on_open
        self.type_hooks = {
            'ping': self.on_ping,
            'welcome': self.on_welcome,
            'confirm_subscription': self.on_subscription_confirmed
            }
        self.message_hooks = {
            'flag_log': self.on_flag,
            'feedback': self.on_feedback,
            'deletion_log': self.on_delete,
            'not_flagged': self.on_not_flagged,
            'statistic': self.on_statistic
            }
        self.last_ping_time = None
        self.sub_id = None

        # Make it easy for subclasses
        self.init_hook()

        self.ws.run_forever()

    def init_hook(self):
        pass

    def on_open(self, ws):
        logging.info('open')

    def on_message(self, ws, message):
        # The demo code uses a thread here but that seems excessive
        try:
            arg = json.loads(message)
        except json.decoder.JSONDecodeError as err:
            ######## TODO:logging
            logging.warn('{err} (message {message})'.format(
                err=err, message=message))
            return
        if 'type' in arg and arg['type'] in self.type_hooks:
            self.type_hooks[arg['type']](ws, arg)
        elif 'message' in arg:
            for key in self.message_hooks:
                if key in arg['message']:
                    self.message_hooks[key](ws, arg)
                    break
            else:
                logging.warn('unrecognized message {arg!r}'.format(arg=arg))
        else:
            logging.warn('unrecognized message {arg!r}'.format(arg=arg))

    def on_ping(self, ws, arg):
        logging.debug('received ping')
        self.last_ping_time = arg['message']

    def on_welcome(self, ws, arg):
        logging.info('sending subscribe')
        ws.send(json.dumps({
            'command': 'subscribe',
            'identifier': json.dumps({
                'channel': 'ApiChannel',
                'key': self.key,
                'command': 'subscribe'
                })}))

    def on_subscription_confirmed(self, ws, arg):
        logging.info('subscription confirmed')
        self.sub_id = arg['identifier']

    def on_flag (self, ws, arg):
        logging.info('flag_log {flag}'.format(flag=arg['message']))

    def on_feedback (self, ws, arg):
        logging.info('feedback {feedback}'.format(feedback=arg['message']))

    def on_delete (self, ws, arg):
        logging.info('deleted {post}'.format(post=arg['message']))

    def on_not_flagged (self, ws, arg):
        logging.info('below auto {post}'.format(post=arg['message']))

    def on_statistic (self, ws, arg):
        logging.info('statistic {post}'.format(post=arg['message']))

    def on_error(self, ws, error):
        logging.warn('{error}'.format(error=error))

    def on_close(self, ws):
        logging.info('close')


class FetchError (Exception):
    pass


class HalflifeClient (ActionCableClient):
    def init_hook (self):
        self.flagged = set()
        self.checker = Halflife(key=self.key)

    def on_flag (self, ws, arg):
        logging.info('flag_log {message}'.format(message=arg['message']))
        link = arg['message']['flag_log']['post']['link']
        if link not in self.flagged:
            self.checker.check(arg['message']['flag_log']['post'])
            self.flagged.update([link])
        else:
            logging.info('Already flagged {link}, not checking again'.format(
                link=link))

    def on_not_flagged (self, ws, arg):
        logging.info('not_flagged {message}'.format(message=arg['message']))
        self.checker.check(arg['message']['not_flagged']['post'])


class MetasmokeApiError(Exception):
    pass


class Halflife ():
    def __init__ (self, key):
        self.key = key

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
            'github.com',
            'goo.gl',
            'google.com',
            'google.ie',
            'youtube.com',
            'youtu.be',
            ]
        ######## TODO: load a pickle?
        self.host_lookup_cache = dict()

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
                if not items[i].startswith(
                        ('Body -', 'Title -', 'Username -', 'Position ')):
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

        self.get_post_metainformation(message)
        weight = message[':meta']['reason_weight']
        post_id = message['id']
        logging.warn('{id}: Check post https:{link} ({weight})'.format(
            id=post_id, link=message[':meta']['link'], weight=weight))
        logging.debug('url: {url}'.format(url=message['link']))
        logging.debug('title: {title}'.format(title=message['title']))
        logging.debug('body: {body}'.format(body=message['body']))
        logging.debug('username: {user}'.format(user=message['username']))
        self.get_post_reasons(message)
        message[':why'] = parse_why(message)
        ######## TODO: don't hardcode limit
        if weight < 280 and any([x['reason_name'].startswith('Blacklisted ')
                for x in message[':reasons']]):
            logging.error(
                '{id}: Blacklisted contents but post still below auto'.format(
                    id=post_id))
        urls = set()
        cleaned_body = strip_code_blocks(message['body'])
        logging.info('Body with code blocks stripped is {0!r}'.format(
            cleaned_body))
        if 'http://' in message['title'] or 'https://' in message['title']:
            urls.update(self.pick_urls(message['title']))
        if '<a href="' in cleaned_body:
            urls.update([frag.split('"')[0]
                for frag in cleaned_body.split('<a href="')[1:]])
        elif 'http://' in cleaned_body or 'https://' in cleaned_body:
            urls.update(self.pick_urls(cleaned_body))

        logging.info('urls are {urls!r}'.format(urls=urls))

        if len(urls) > 0:

            url_result = self.check_urls(urls)

            for url in url_result:

                logging.warn('{id}: Extracted URL {url}'.format(
                    id=post_id, url=url))

                if 'domain_check' not in url_result[url]:
                    logging.debug(
                        '{id}: No domain_check result for {url}'.format(
                            id=post_id, url=url))
                    ######## TODO: maybe check :why here too?
                else:
                    for host in url_result[url]['domain_check']:
                        if not url_result[url]['domain_check'][host]:
                            if host in message[':why']:
                                logging.warn('{id}: {host} matched: '
                                    '{why}'.format(id=post_id, host=host,
                                        why='; '.join(message[':why'][host])))
                            else:
                                logging.error('{id}: {host} is not blacklisted '
                                    'or watched'.format(id=post_id, host=host))
                        else:
                            logging.warn('{id}: {host} is {what}'.format(
                                id=post_id, host=host,
                                what=url_result[url]['domain_check'][host]))

                if 'request_check' in url_result[url]:
                    status = url_result[url]['request_check'].status_code
                    if status != 200:
                        logging.warn('{id}: HTTP status {status} for {url}'
                            .format(id=post_id, status=status, url=url))

                if 'go-url' in url_result[url]:
                    for go_url in url_result[url]['go-url']:
                        logging.warn('{id}: Wordpress promotion URL {url} '
                            'redirects to {dest}'.format(
                                id=post_id, url=go_url,
                                    dest=url_result[url]['go-url'][go_url]))

                if 'dns_check' not in url_result[url] or \
                        'host' not in url_result[url]['dns_check']:
                    logging.debug('{id}: no dns_check result for {url}'.format(
                        id=post_id, url=url))
                else:
                    host = url_result[url]['dns_check']['host']
                    if url_result[url]['dns_check'][':cached']:
                        logging.info('{id}: {host}: cached DNS result, '
                            'not reporting again'.format(id=post_id, host=host))
                    else:
                        logging.warn('{id}: {host}: ns {ns}'.format(
                            id=post_id, host=host,
                            ns=url_result[url]['dns_check']['ns']))
                        for ip in url_result[url]['dns_check']['a']:
                            if ip in url_result[url]['dns_check']['rdns']:
                                rdns = url_result[url]['dns_check']['rdns'][ip]
                                if rdns == None:
                                    rdns = ''
                                if len(rdns) == 1:
                                    rdns = rdns[0]
                            else:
                                rdns = ''
                            logging.warn('{id}: {host}: ip {ip} '
                                '({rdns})'.format(
                                    id=post_id, host=host, ip=ip, rdns=rdns))

                if 'tail_check' not in url_result[url]:
                    logging.debug('{id}: no tail from URL {url}'.format(
                        id=post_id, url=url))
                else:
                    for tail, result in url_result[url]['tail_check'].items():
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
                        if not result or result == 'watched':
                            tail_re = tail.replace('-', '[^A-Za-z0-9_]?')
                            tail_query = self.tp_query(tail_re)
                            logging.warn('{id}: regex {re} search:'
                                ' {tp}/{all} hits'.format(
                                    id=post_id,
                                    re=tail.replace('-', r'\W?'),
                                    tp=tail_query['tp_count'],
                                    all=len(tail_query['hits'])))
                        if not result:
                            result = 'not blacklisted or watched'
                        logging.warn(
                            '{id}: URL tail {tail} is {result}'.format(
                                id=post_id, tail=tail, result=result))

                if 'metasmoke' not in url_result[url]:
                    logging.debug('{id}: no metasmoke result for {url}'.format(
                        id=post_id, url=url))
                else:
                    hits = url_result[url]['metasmoke']
                    count = len(hits['hits'])
                    if count == 0:
                        logging.warn('{id}: {host}: No metasmoke hits'.format(
                            id=post_id, host=host))
                    elif count == 1:
                        logging.warn('{id}: {host}: first hit'.format(
                            id=post_id, host=host))
                    else:
                        logging.warn(
                            '{id}: {host}: {tp}/{all} over {span}'.format(
                                id=post_id, host=host, tp=hits['tp_count'],
                                all=count, span=hits['timespan']))


    def api_query(self, route, filter=None):
        logging.info('query: /api/{route}'.format(route=route))
        params = {'key': self.key}
        if filter:
            params['filter'] = filter
        req = requests.get(
            'https://metasmoke.erwaysoftware.com/api/{route}'.format(
                route=route),
            params=params)
        result = json.loads(req.text)
        logging.info('query result: {0!r}'.format(result))
        if 'error' in result:
            raise MetasmokeApiError(error_message)
        return result

    def _api_id_query(self, message, route_pattern, filter=None):
        id = message['id']
        return self.api_query(route_pattern.format(id), filter=filter)

    def get_post_metainformation(self, message, filter=None):
        if ':meta' not in message:
            meta = self._api_id_query(message, 'posts/{0}', filter=filter)
            message[':meta'] = meta['items'][0]

    def get_post_reasons(self, message):
        reasons = self._api_id_query(message, 'post/{0}/reasons')
        message[':reasons'] = reasons['items']

    def pick_urls(self, string):
        """
        Very quick and dirty heuristic URL extractor
        """
        urls = []
        for frag in string.split('http')[1:]:
            logging.info('examining fragment {frag}'.format(frag=frag))
            if frag.startswith('s://') or frag.startswith('://'):
                candidate = 'http' + frag.split()[0]
                candidate = candidate.split('">')[0]
                candidate = candidate.rstrip('">')
                if '%20' in candidate:
                    continue
                urls.append(candidate)
        return urls

    def check_urls(self, urls, recurse=True):
        '''
        Check a list of URLs.

        With recurse=False, don't attempt to fetch.
        '''
        def _fetch (url):
            """
            Use requests to fetch the URL, pretend to be a browser.
            """
            from requests.exceptions import ConnectionError
            try:
                response = requests.get(url, timeout=20,
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
                logging.info('Status {0} for URL {1}'.format(
                    response.status_code, url))
                logging.debug('Fetched {0}'.format(response.text))
                return response
            except (ConnectionError) as exc:
                logging.warn('Failed to fetch URL {0} ({1!r})'.format(url, exc))
                raise FetchError(str(exc))

        seen = set()
        result = dict()
        for url in urls:
            result[url] = {}
            parts = url.split('/', maxsplit=3)
            if len(parts) < 4:
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
                if host in self.domain_whitelist:
                    result[url]['domain_check'] = {host: 'whitelisted'}
                    continue
                elif self.listed('^' + host_re, 'blacklisted_websites.txt'):
                    result[url]['domain_check'] = {host: 'blacklisted'}
                else:
                    if self.listed('\t' + host_re, 'watched_keywords.txt'):
                        result[url]['domain_check'] = {host: 'watched'}
                    else:
                        result[url]['domain_check'] = {host: None}
                    result[url]['metasmoke'] = self.domain_query(host)

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

            try:
                if recurse:
                    response = _fetch(url)

                    result[url]['request_check'] = response

                    if response.status_code == 200:
                        if '<meta name="generator" content="WordPress' not \
                                in response.text:
                            logging.debug('Not a WordPress page apparently')
                        else:
                            logging.debug('Found WordPress <meta> tag')
                            srcset_urls = set()
                            for line in response.text.split('\n'):
                                if ' srcset="' in line and '><img ' in line:
                                    for surl in self.pick_urls(line):
                                        if surl.endswith('.jpg') or \
                                                '.jpg?' in surl:
                                            logging.debug('Skip JPG URL {0}'
                                                .format(surl))
                                            continue
                                        if surl.endswith('.png') or \
                                                '.png?' in surl:
                                            logging.debug('Skip PNG URL {0}'
                                                .format(surl))
                                            continue
                                        srcset_urls.add(surl)
                            logging.debug('srcset= URLS: {0!r}'.format(
                                srcset_urls))
                            if len(srcset_urls) > 5:
                                logging.info('List of URLs too long, skipping')
                                srcset_urls = []
                            for go_url in srcset_urls:
                                try:
                                    go_response = _fetch(go_url)
                                except FetchError as exc:
                                    logging.warn('Failed to fetch {0} ({1!r})'
                                        .format(go_url, exc))
                                    continue
                                if go_response.url == go_url:
                                    logging.debug('No redirect {0}'.format(
                                        go_url))
                                else:
                                    if 'go-url' not in result[url]:
                                        result[url]['go-url'] = dict()
                                    result[url]['go-url'][
                                        go_url] = go_response.url
                                    result.update(self.check_urls(
                                        [go_response.url], recurse=False))

                except FetchError as exc:
                    logging.warn('Failed to fetch {0} ({1!r})'.format(url, exc))

        return result

    def listed(self, host_re, listfile, escape=True):
        ######## TODO: maybe replace with a metasmoke query
        ######## FIXME: if the listed regex is broader, this will miss it
        if escape:
            host_re = host_re.replace('\\', '\\\\')
        try:
            logging.debug('running {0!r}'.format(['grep', '-qis', host_re, listfile]))
            subprocess.run(['grep', '-qis', host_re, listfile], check=True)
            logging.debug('returning True')
            return True
        except subprocess.CalledProcessError:
            logging.debug('returning False')
            return False

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
                ######## FIXME: ad-hoc filter
                hit, filter='AAAAAAAAAAO//gAAAAAAAUA=')
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
                    logging.warn(
                        'Post {id} below auto ({weight}) {span} ago'.format(
                            id=hit['id'], weight=wt,
                            span=datetime.datetime.now()-post_date))
                    below_auto += 1
            else:
                logging.info('{count} results; not getting weights'.format(
                count=len(hits)))
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

    def domain_query (self, domain, is_regex=False):
        if is_regex:
            domain = domain.replace(r'\W', '[^A-Za-z0-9_]')
        else:
            domain = domain.replace('.', r'\.')
        return self.tp_query(domain)

    def dns (self, host):
        ######## TODO: maybe replace with dnspython
        def _dig (query, host):
            q = subprocess.run(['dig', '+short', '-t', query, host],
                check=False, stdout=subprocess.PIPE, universal_newlines=True)
            if q.stdout == '\n':
                return []
            return q.stdout.rstrip('\n').split('\n')

        def isip (addr):
            for ch in ['.'] + [str(i) for i in range(0,10)]:
                addr = addr.replace(ch, '')
            return addr == ''

        if host in self.host_lookup_cache:
            self.host_lookup_cache[host][':cached'] = True
            return self.host_lookup_cache[host]

        result = {'host': host, 'ns': _dig('ns', host), ':cached': False}

        if any([x.endswith('root-servers.net.') for x in result['ns']]):
            logging.warn('NS contains root-servers.net.; abandoning')
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
                raddr = '.'.join(
                    reversed(cleanaddr.split('.'))) + '.in-addr.arpa.'
                rdns = _dig('cname', raddr)
                if rdns == ['']:
                    rdns = _dig('ptr', raddr)
                if rdns == ['']:
                    rdns = None
                result['rdns'][addr] = rdns

        ip6 = _dig('aaaa', host)
        result['aaaa'] = ip6
        ######## TODO: reverse DNS for IPv6

        self.host_lookup_cache[host] = result
        return result


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.WARN, format='%(module)s:%(asctime)s:%(message)s')
    with open('halflife.conf', 'r') as conffile:
        conf = json.loads(conffile.read())
    h = HalflifeClient(key=conf['metasmoke-key'])
