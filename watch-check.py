#!/usr/bin/env python3

import logging
from datetime import timedelta

import halflife as hl

class WatchChecker:
    def __init__(self, key):
        self.metasmoke_key = key

    def domain_result(self, domain):
        halflife = hl.Halflife(key=self.metasmoke_key)
        result = halflife.domain_query(domain, is_regex=True)
        result['domain'] = domain
        result['hitcount'] = len(result['hits'])
        return result

    def watch_loop(self, watchfilename):
        """
        Loop over watch file; yield result for each domain in file.
        """
        with open(watchfilename, 'r') as opened:
            for line in opened:
                fields = line.split('\t')
                domain = fields[-1].rstrip('\n')
                yield self.domain_result(domain)

    def eligible(self, result):
        if not hasattr(self, 'days180'):
            self.days180 = timedelta(days=-180)
        result['info'] = '{0}/{1} over {2}{3}'.format(
            result['tp_count'], result['hitcount'], result['timespan'],
            ' ({0} below auto)'.format(result['below_auto']) \
                if result['below_auto'] else '')
        if result['hitcount'] != result['tp_count']:
            result['why'] = 'TP count < hits'
            return False
        if result['hitcount'] >= 20:
            result['why'] = '20+ hits, all TP'
            return True
        elif result['hitcount'] >= 10:
            if result['timespan'] <= self.days180:
                result['why'] = '10+ hits in 180 days, all TP'
                return True
            else:
                result['why'] = '10+ hits but over more than 180 days'
                return False
        elif result['hitcount'] >= 5 and result['timespan'] <= self.days180 \
                and result['below_auto'] > 0:
            result['why'] = '5+ hits in 180 days, some below auto'
            return True
        else:
            result['why'] = '(fell through)'
            return False

    def watch_check(self, watchfilename):
        for result in self.watch_loop(watchfilename):
            eligible_p = self.eligible(result)
            logging.warn('{0}: {1} -- {2} because {3} '.format(
                result['domain'], result['info'], eligible_p, result['why']))
            if eligible_p:
                print('{0}: {1} ({2})'.format(
                    result['domain'], result['info'], result['why']))


def main():
    import logging
    import json
    #logging.basicConfig(level=logging.INFO, format='%(module)s:%(message)s')
    logging.basicConfig(level=logging.WARN, format='%(module)s:%(message)s')
    with open('halflife.conf', 'r') as conffile:
        config = json.loads(conffile.read())
    WatchChecker(config['metasmoke-key']).watch_check('./watched_keywords.txt')

if __name__ == '__main__':
    main()
