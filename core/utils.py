import requests
import yaml
import logging
import os
import time
from urllib.parse import urlparse
from threading import Lock

_config = None
_config_lock = Lock()

def load_config(config_path="config.yaml"):
    global _config
    with _config_lock:
        if _config is None:
            with open(config_path, 'r') as f:
                _config = yaml.safe_load(f)
    return _config

def setup_logger(name, log_file=None, level=None):
    cfg = load_config()
    if level is None:
        level = cfg['logging']['level']
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level))
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    # File handler
    output_dir = cfg['logging']['output_dir']
    os.makedirs(output_dir, exist_ok=True)
    if log_file is None:
        log_file = os.path.join(output_dir, f"{name}.log")
    fh = logging.FileHandler(log_file)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    return logger

class Requester:
    def __init__(self, proxy=None, timeout=None, headers=None):
        cfg = load_config()
        self.timeout = timeout or cfg['request']['timeout']
        self.session = requests.Session()
        # Proxy
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        elif cfg['proxy']['enabled']:
            self.session.proxies = {
                'http': cfg['proxy']['http'],
                'https': cfg['proxy']['https']
            }
        # Headers
        self.session.headers.update(cfg['request']['headers'])
        self.session.headers['User-Agent'] = cfg['request']['user_agent']
        if headers:
            self.session.headers.update(headers)
        self.logger = setup_logger('Requester')
    
    def get(self, url, params=None, **kwargs):
        delay = load_config()['scan']['delay_between_requests']
        time.sleep(delay)
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout, **kwargs)
            self.logger.debug(f"GET {resp.status_code} {url}")
            return resp
        except Exception as e:
            self.logger.error(f"GET failed: {e}")
            return None
    
    def post(self, url, data=None, json=None, **kwargs):
        delay = load_config()['scan']['delay_between_requests']
        time.sleep(delay)
        try:
            resp = self.session.post(url, data=data, json=json, timeout=self.timeout, **kwargs)
            self.logger.debug(f"POST {resp.status_code} {url}")
            return resp
        except Exception as e:
            self.logger.error(f"POST failed: {e}")
            return None
