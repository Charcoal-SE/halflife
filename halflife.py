#!/usr/bin/env python3

import datetime
import json
import logging
import subprocess

import requests
import websocket


MSKey = 'invalid'


######## TODO: maybe replace with actioncable-zwei
# https://github.com/tobiasfeistmantl/python-actioncable-zwei
class ActionCableClient ():
    def __init__(
            self,
            ws_url='wss://metasmoke.erwaysoftware.com/cable',
            enable_trace=False):
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
                'key': MSKey,
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


class MetaSmokeSearch ():
    def __init__ (self, expr, scope='body', regex=False):
        regexstr = '1' if regex else '0'
        if scope == 'body':
            query = {'body': expr, 'body_is_regex': regexstr}
        elif scope == 'title':
            query = {'title': expr, 'title_is_regex': regexstr}
        else:
            raise KeyError(
                'scope must be either "body" or "title", not {scope}'.format(
                    scope=scope))
        req = requests.get(
            'https://metasmoke.erwaysoftware.com/search.json',
            params=query)
        self.reqs = [req]
        self.result = json.loads(req.text)
        self.autoflagging_threshold = 280
        self.blacklist_thres = 30  # 30 hits or more means blacklist
        self.auto_age_thres = 180  # 180 days == 6 months
        self.auto_thres = 20       # 20 hits in 180 days means blacklist
        self.below_auto = []
        ######## TODO: fetch remaining results if is_more=True

    def update (self, expr, scope='body', regex=False):
        """
        Run another query and merge in results.
        """
        other = MetaSmokeSearch(expr, scope=scope, regex=regex)
        self.reqs.append(other.reqs[0])
        for k in other.result:
            if k['id'] not in self.result:
                self.result.append(k)
        self.result = sorted(self.result, key=lambda x: x['id'])

    def weight (self, post_id):
        """
        Brute-force autoflagging weight by scraping the post page (bletch)
        """
        req = requests.get(
            'https://metasmoke.erwaysoftware.com/post/{id}'.format(id=post_id))
        parts = req.text.split('<p class="text-muted">Reason weight: ')
        if len(parts) == 1:
            raise ValueError(
                'Scraping reason weight failed. Text={text!r}'.format(
                    text=req.text))
        wt = int(parts[1].split('</p>')[0])
        logging.info('Post {id} weight {weight}'.format(id=post_id, weight=wt))
        return wt

    def update_weights (self):
        hits = len(self.result)
        if hits < self.blacklist_thres and hits == self.tp_count():
            age_thres = datetime.datetime.utcnow() - datetime.timedelta(
                days=self.auto_age_thres)
            for post in reversed(self.result):
                post_date = self.post_date(post)
                if post_date < age_thres:
                    logging.info(
                        'Post {id} too old {date}, ignoring weight'.format(
                            id=post['id'], date=post_date))
                    break
                wt = self.weight(post['id'])
                post['weight'] = wt
                if wt < self.autoflagging_threshold and \
                        not post['is_naa'] and not post['is_fp']:
                    logging.warn(
                        'Post {id} below auto ({weight}) {when} ago'.format(
                            id=post['id'], weight=wt,
                                when=datetime.datetime.utcnow()-post_date))
                    break
        else:
            logging.info('{count} results; not getting weights'.format(
                count=len(self.result)))

    def count (self):
        return len(self.result)

    def tp (self):
        """
        This is "proper" true positives, as in "is_tp" is true and neither
        "is_naa" nor "is_fp" are also true.
        """
        return [x for x in self.result
            if x['is_tp'] and not x['is_naa'] and not x['is_fp']]

    def tp_count (self):
        return len(self.tp())

    def post_date (self, post):
        return datetime.datetime.strptime(
            post['created_at'][0:19], '%Y-%m-%dT%H:%M:%S')

    def span (self):
        return self.post_date(self.result[-1]) - self.post_date(self.result[0])


class HalflifeClient (ActionCableClient):
    def init_hook (self):
        self.flagged = set()
        self.checker = Halflife()

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


class Halflife ():
    def __init__ (self):
        self.domain_whitelist = ['i.stack.imgur.com', 'stackoverflow.com']
        ######## TODO: load a pickle?
        self.host_lookup_cache = dict()

    def check (self, message):
        self.get_post_metainformation(message)
        weight = message[':meta']['reason_weight']
        post_id = message['id']
        logging.warn('Check post {id} https:{link} ({weight})'.format(
            id=post_id, link=message[':meta']['link'], weight=weight))
        logging.debug('url: {url}'.format(url=message['link']))
        logging.debug('title: {title}'.format(title=message['title']))
        logging.debug('body: {body}'.format(body=message['body']))
        logging.debug('username: {user}'.format(user=message['username']))
        self.get_post_reasons(message)
        ######## TODO: don't hardcode limit
        # (currently a MetaSmokeSearch variable, should be declared here?)
        if weight < 280 and any([x['reason_name'].startswith('Blacklisted ')
                for x in message[':reasons']]):
            logging.error(
                '{id}: Blacklisted contents but post still below auto'.format(
                    id=post_id))
        urls = set()
        if 'http://' in message['title'] or 'https://' in message['title']:
            urls.update(self.pick_urls(message['title']))
        if '<a href="' in message['body']:
            urls.update([frag.split('"')[0]
                for frag in message['body'].split('<a href="')[1:]])
        elif 'http://' in message['body'] or 'https://' in message['body']:
            urls.update(self.pick_urls(message['body']))

        logging.info('urls are {urls!r}'.format(urls=urls))

        if len(urls) > 0:

            url_result = self.check_urls(urls)

            for url in url_result:

                if 'domain_check' not in url_result[url]:
                    logging.debug(
                        '{id}: No domain_check result for {url}'.format(
                            id=post_id, url=url))
                else:
                    for host in url_result[url]['domain_check']:
                        if not url_result[url]['domain_check'][host]:
                            logging.error('{id}: {host} is not blacklisted '
                                'or watched'.format(id=post_id, host=host))
                        else:
                            logging.warn('{id}: {host} is {what}'.format(
                                id=post_id, host=host,
                                what=url_result[url]['domain_check'][host]))

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

                if 'metasmoke' not in url_result[url]:
                    logging.debug('{id}: no metasmoke result for {url}'.format(
                        id=post_id, url=url))
                else:
                    mshits = url_result[url]['metasmoke']
                    count = mshits.count()
                    if count == 0:
                        logging.warn('{id}: {host}: No metasmoke hits'.format(
                            id=post_id, host=host))
                    elif count == 1:
                        logging.warn('{id}: {host}: first hit'.format(
                            id=post_id, host=host))
                    else:
                        tp_count = mshits.tp_count()
                        logging.warn(
                            '{id}: {host}: {tp}/{all} hits over {span}'.format(
                                id=post_id, host=host, tp=tp_count, all=count,
                                span=mshits.span()))

    def api_id_query(self, message, route_pattern):
        id = message['id']
        req = requests.get(
            'https://metasmoke.erwaysoftware.com/{route}'.format(
                route=route_pattern.format(id=id)),
            params={'key': MSKey})
        return json.loads(req.text)

    def get_post_metainformation(self, message):
        meta = self.api_id_query(message, '/api/posts/{id}')
        message[':meta'] = meta['items'][0]

    def get_post_reasons(self, message):
        reasons = self.api_id_query(message, '/api/post/{id}/reasons')
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
                candidate.rstrip('">')
                if '%20' in candidate:
                    continue
                urls.append(candidate)
        return urls

    def check_urls(self, urls):
        seen = set()
        result = dict()
        for url in urls:
            result[url] = {}
            parts = url.split('/', maxsplit=3)
            if len(parts) < 4:
                parts.extend([None] * (4-len(parts)))
            proto, _, host, tail = parts
            if host.startswith('www.'):
                host = host[4:]
            if host in seen:
                continue
            seen.update([host])
            host_re = host.replace('.', r'\.')
            if host in self.domain_whitelist:
                result[url]['domain_check'] = {host: 'whitelisted'}
                continue
            elif self.listed(host_re, 'blacklisted_websites.txt'):
                result[url]['domain_check'] = {host: 'blacklisted'}
            else:
                if self.listed(host, 'watched_keywords.txt'):
                    result[url]['domain_check'] = {host: 'watched'}
                else:
                    result[url]['domain_check'] = {host: None}
                result[url]['metasmoke'] = self.query(host)

            ######## TODO: examine tail

            result[url]['dns_check'] = self.dns(host)

        return result

    def listed(self, host_re, listfile):
        ######## TODO: maybe replace with a metasmoke query
        try:
            subprocess.run(['fgrep', '-qis', host_re, listfile], check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def query (self, host):
        host_re = r'\b{host}\b'.format(host=host.replace('.', r'\.'))
        host_re = host.replace('.', r'\.')  ######## FIXME: temporary
        hits = MetaSmokeSearch(host_re, scope='title', regex=True)
        ######## TODO: separate title vs body results
        hits.update(host_re, scope='body', regex=True)
        if hits.count() > 1 and hits.tp_count() < hits.blacklist_thres:
            hits.update_weights()
        return hits

    def dns (self, host):
        ######## TODO: maybe replace with dnspython
        def _dig (query, host):
            q = subprocess.run(['dig', '+short', '-t', query, host],
                check=True, stdout=subprocess.PIPE, universal_newlines=True)
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
    MSKey = conf['metasmoke-key']
    h = HalflifeClient()
