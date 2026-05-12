# core/utils.py
import requests
import yaml
import logging
import os
import time
from urllib.parse import urlparse
from threading import Lock

# Global config
config = None
config_lock = Lock()

def load_config(config_path="config.yaml"):
    global config
    with config_lock:
        if config is None:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
    return config

def setup_logger(name, log_file=None, level=None):
    if level is None:
        level = load_config()['logging']['level']
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level))
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    # File handler
    if log_file is None:
        log_file = os.path.join(load_config()['logging']['output_dir'], f"{name}.log")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    fh = logging.FileHandler(log_file)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    return logger

class Requester:
    def __init__(self, proxy=None, timeout=None, headers=None):
        cfg = load_config()
        self.timeout = timeout or cfg['request']['timeout']
        self.session = requests.Session()
        if proxy or cfg['proxy']['enabled']:
            proxy_url = proxy or cfg['proxy']['http']
            self.session.proxies = {'http': proxy_url, 'https': proxy_url}
        self.session.headers.update(cfg['request']['headers'])
        if headers:
            self.session.headers.update(headers)
        self.session.headers['User-Agent'] = cfg['request']['user_agent']
        self.logger = setup_logger('Requester')
    
    def get(self, url, params=None, **kwargs):
        time.sleep(load_config()['scan']['delay_between_requests'])
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout, **kwargs)
            self.logger.debug(f"GET {resp.status_code} {url}")
            return resp
        except Exception as e:
            self.logger.error(f"Request failed: {e}")
            return None
    
    def post(self, url, data=None, json=None, **kwargs):
        time.sleep(load_config()['scan']['delay_between_requests'])
        try:
            resp = self.session.post(url, data=data, json=json, timeout=self.timeout, **kwargs)
            self.logger.debug(f"POST {resp.status_code} {url}")
            return resp
        except Exception as e:
            self.logger.error(f"Request failed: {e}")
            return None
