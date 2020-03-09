import requests
import json
import datetime
import logging


class MetasmokeApiError(Exception):
    pass


class DisabledError(Exception):
    """
    Regex queries are disabled for now.
    """
    pass


class MetasmokeApi():
    def __init__(self, key,
            baseurl='https://metasmoke.erwaysoftware.com/api/v2.0/'):
        self.baseurl = baseurl
        self.key = key

    def query(self, route, filterexp=None):
        params = {'key': self.key}
        if filterexp:
            params['filter'] = filterexp
        else:
            params['filter'] = ''

        logging.info('query: /api/v2/%s (params: %s)', route, params)
        req = requests.get('{0}{1}'.format(self.baseurl, route), params=params)
        try:
            result = req.json()
            logging.info('query result: %r', result)
        except json.decoder.JSONDecodeError:
            logging.error(
                'Query %s did not return valid JSON: %r', route, req.text)
            result = {'error': 'Invalid JSON {0!r}'.format(req.text)}
            raise
        if 'error' in result:
            raise MetasmokeApiError(result['error'])
        return result


    # ######## FIXME: don't mix API and messages

    def _api_id_query(self, message, route_pattern, filterexp=None):
        id = message['id']
        return self.query(route_pattern.format(id), filterexp=filterexp)

    def get_post_metainformation(self, message):
        if ':meta' not in message:
            meta = self._api_id_query(message, 'posts/{0}')
            if 'items' in meta and len(meta['items']) > 0:
                message[':meta'] = meta['items'][0]
                domains = self._api_id_query(message, 'posts/{0}/domains')
                message[':domains'] = domains['items']
                reasons = self._api_id_query(message, 'posts/{0}/reasons')
                message[':reasons'] = reasons['items']
                message[':weight'] = sum(x['weight'] for x in reasons['items'])
                return True
            else:
                logging.warning(
                    'No results for posts/%s (result: %r)', message['id'], meta)
                return False

    def domain_query(self, domain_id):
        post_date_max = None
        post_date_min = None
        domain_feedback = {'tp': 0, 'fp': 0, 'naa': 0, ':all': 0}

        posts = self.query('domains/{0}/posts'.format(domain_id))

        for item in posts['items']:
            post_date = datetime.datetime.strptime(
                item['created_at'][0:19], '%Y-%m-%dT%H:%M:%S')
            if post_date_max is None or post_date > post_date_max:
                post_date_max = post_date
            if post_date_min is None or post_date < post_date_min:
                post_date_min = post_date


            feedbacks = self.query('feedbacks/post/{0}'.format(item['id']))

            count = {'tp': 0, 'fp': 0, 'naa': 0, ':all': 0}
            for feedback in feedbacks['items']:
                logging.debug('feedback %s on post %s is %s', feedback['id'],
                    feedback['post_id'], feedback['feedback_type'])
                count[':all'] +=1

                ftype_value = feedback['feedback_type']
                for ftype in {'fp', 'tp', 'naa'}:
                    if ftype_value.startswith(ftype):
                        count[ftype] += 1
                        break
                else:
                    logging.warning('feedback %s on post %s: unknown type %s',
                        feedback['id'], feedback['post_id'],
                            feedback['feedback_type'])

            logging.info('feedback count for post %s: %s', item['id'], count)

            if count[':all'] > 0 and count['tp']/count[':all'] >= 0.9:
                domain_feedback['tp'] += 1
            if count['naa'] > 0:
                domain_feedback['naa'] += 1
            if count['fp'] > 0:
                domain_feedback['fp'] += 1
            domain_feedback[':all'] += 1

        posts[':feedback'] = domain_feedback
        if post_date_min and post_date_max:
            posts[':timespan'] = post_date_max - post_date_min
        else:
            posts[':timespan'] = datetime.timedelta()

        return posts
