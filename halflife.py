#!/usr/bin/env python3

import datetime
import json
import logging
import subprocess

import requests
import websocket


MSKey = 'invalid'


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
        ######## TODO: fetch remaining results if is_more=True

    def update (self, expr, scope='body', regex=False):
        """
        Run another query and merge in results.
        """
        other = MetaSmokeSearch(expr, scope=scope, regex=regex)
        self.reqs.append(other.reqs[0])
        oldresult = [x['id'] for x in self.result]
        for k in other.result:
            if k['id'] not in oldresult:
                oldresult.append(k)
        self.result = sorted(oldresult, key=lambda x: x['id'])

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

    def span (self):
        def _strptime(index):
            return datetime.datetime.strptime(
                self.result[index]['created_at'][0:19],
                '%Y-%m-%dT%H:%M:%S')

        def start_span ():
            return _strptime(0)

        def end_span ():
            return _strptime(-1)

        return end_span() - start_span()


class Halflife (ActionCableClient):
    def init_hook (self):
        self.flagged = set()
        self.domain_whitelist = ['i.stack.imgur.com', 'stackoverflow.com']

    def on_flag (self, ws, arg):
        logging.info('flag_log {message}'.format(message=arg['message']))
        link = arg['message']['flag_log']['post']['link']
        if link not in self.flagged:
            self.check(arg['message']['flag_log']['post'])
            self.flagged.update([link])
        else:
            logging.info('Already flagged {link}, not checking again'.format(
                link=link))

    def on_not_flagged (self, ws, arg):
        logging.info('not_flagged {message}'.format(message=arg['message']))
        self.check(arg['message']['not_flagged']['post'])

    def check (self, message):
        logging.info('url: {url}'.format(url=message['link']))
        logging.info('title: {title}'.format(title=message['title']))
        logging.info('body: {body}'.format(body=message['body']))
        logging.info('username: {user}'.format(user=message['username']))
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
            self.check_urls(urls)

    def pick_urls(self, string):
        """
        Very quick and dirty heuristic URL extractor
        """
        urls = []
        for frag in string.split('http')[1:]:
            logging.info('examining fragment {frag}'.format(frag=frag))
            if frag.startswith('s://') or frag.startswith('://'):
                urls.append('http' + frag.split()[0])
        return urls

    def check_urls(self, urls):
        seen = set()
        for url in urls:
            if url in seen:
                continue
            seen.update([url])
            parts = url.split('/', maxsplit=3)
            if len(parts) < 4:
                parts.extend([None] * (4-len(parts)))
            proto, _, host, tail = parts
            if host.startswith('www.'):
                host = host[4:]
            host_re = host.replace('.', r'\.')
            if host in self.domain_whitelist:
                continue
            elif self.listed(host_re, 'blacklisted_websites.txt'):
                logging.warn('{host} is blacklisted'.format(host=host))
            else:
                if self.listed(host, 'watched_keywords.txt'):
                    logging.warn('{host} is watched'.format(host=host))
                else:
                    logging.error('{host} is not blacklisted or watched'.format(
                        host=host))
                #self.query(host)
            ######## FIXME: temporary
            self.query(host)
            ######## TODO: examine tail

    def listed(self, host_re, listfile):
        try:
            subprocess.run(['fgrep', '-nis', host_re, listfile], check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def query (self, host):
        host_re = r'\b{host}\b'.format(host=host.replace('.', r'\.'))
        host_re = host.replace('.', r'\.')  ######## FIXME: temporary
        hits = MetaSmokeSearch(host_re, scope='title', regex=True)
        hits.update(host_re, scope='body', regex=True)
        count = hits.count()
        if count == 0:
            logging.warn('No metasmoke hits for {host}'.format(host=host))
        elif count == 1:
            logging.warn('{host}: {tp}/{count} hit'.format(
                host=host, tp=hits.tp_count(), count=count))
        else:
            logging.warn('{host}: {tp}/{count} hits over {span}'.format(
                host=host, tp=hits.tp_count(), count=count, span=hits.span()))


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.WARN, format='%(module)s:%(asctime)s:%(message)s')
    with open('halflife.conf', 'r') as conffile:
        conf = json.loads(conffile.read())
    MSKey = conf['metasmoke-key']
    h = Halflife()
