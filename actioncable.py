import json
import logging

import websocket


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
            on_message=lambda ws, msg: self.on_message(ws, msg),
            on_error=lambda ws, err: self.on_error(ws, err),
            on_close=lambda ws: self.on_close(ws))
        self.ws.on_open = lambda ws: self.on_open(ws)
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
        self.event_hooks = {
            'Post': {
                'create': self.on_event_post_create
                }
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
        #except json.decoder.JSONDecodeError as err:
        except Exception as err:        
            ######## TODO:logging
            logging.warning('%s (message %s)', err, message)
            return            
        if 'type' in arg and arg['type'] in self.type_hooks:
            self.type_hooks[arg['type']](ws, arg)
        elif 'message' in arg:
            if 'event_class' in arg['message'] \
                    and 'event_type' in arg['message']:
                if arg['message']['event_class'] in self.event_hooks:
                    hook_dict = self.event_hooks[arg['message']['event_class']]
                    if arg['message']['event_type'] in hook_dict:
                        return hook_dict[arg['message']['event_type']](ws, arg)
            # else:
            for key in self.message_hooks:
                if key in arg['message']:
                    self.message_hooks[key](ws, arg)
                    break
            else:
                logging.warning('unrecognized message %r', arg)
        else:
            logging.warning('unrecognized message %r', arg)

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
                'command': 'subscribe',
                'events': 'posts#create'
                })}))

    def on_subscription_confirmed(self, ws, arg):
        logging.info('subscription confirmed')
        self.sub_id = arg['identifier']

    def on_flag (self, ws, arg):
        logging.info('flag_log %s', arg['message'])

    def on_feedback (self, ws, arg):
        logging.info('feedback %s', arg['message'])

    def on_delete (self, ws, arg):
        logging.info('deleted %s', arg['message'])

    def on_not_flagged (self, ws, arg):
        logging.info('below auto %s', arg['message'])

    def on_statistic (self, ws, arg):
        logging.info('statistic %s', arg['message'])

    def on_error(self, ws, error):
        logging.warning(error)

    def on_close(self, ws):
        logging.info('close')

    def on_event_post_create(self, ws, message):
        logging.info('events:Post:create')
