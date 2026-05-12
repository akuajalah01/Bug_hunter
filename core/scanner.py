# core/scanner.py
import re
from core.utils import Requester, load_config, setup_logger
from core.payloads import sqli_payloads, xxe_payloads, lfi_payloads, rce_payloads

class Scanner:
    def __init__(self, target_url, proxy=None):
        self.target = target_url.rstrip('/')
        self.req = Requester(proxy=proxy)
        self.logger = setup_logger('Scanner')
        self.cfg = load_config()
    
    def detect_sqli(self, param, test_value="1"):
        """Deteksi SQL injection (boolean & time based) dengan payloads"""
        base_url = f"{self.target}?{param}={test_value}"
        baseline_resp = self.req.get(base_url)
        if not baseline_resp:
            return False, None
        
        for payload in sqli_payloads.SQLI_PAYLOADS:
            test_url = f"{self.target}?{param}={test_value}{payload}"
            import time
            start = time.time()
            resp = self.req.get(test_url)
            elapsed = time.time() - start
            
            # Time based
            if "SLEEP" in payload.upper() or "DELAY" in payload.upper():
                if elapsed > 5:
                    return True, f"time_based_sqli ({payload})"
            
            # Boolean based
            if resp and len(resp.text) != len(baseline_resp.text):
                # Cek ulang dengan payload ' AND 1=2 (beda konten)
                continue
        
        # Error based detection (regex)
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"ORA-[0-9]{5}",
            r"PostgreSQL.*ERROR"
        ]
        test_payload = "' OR 1=1-- -"
        test_url = f"{self.target}?{param}={test_payload}"
        resp = self.req.get(test_url)
        if resp:
            for pattern in error_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    return True, f"error_based_sqli ({pattern})"
        return False, None
    
    def detect_xss(self, param, test_value="test"):
        """Deteksi refleksi XSS sederhana"""
        payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>"]
        for payload in payloads:
            test_url = f"{self.target}?{param}={test_value}{payload}"
            resp = self.req.get(test_url)
            if resp and payload in resp.text:
                return True, f"reflected_xss ({payload})"
        return False, None
    
    def detect_lfi(self, param, test_value="test"):
        """Deteksi Local File Inclusion dengan payload file sistem"""
        payloads = lfi_payloads.LFI_PAYLOADS
        for payload in payloads:
            test_url = f"{self.target}?{param}={payload}"
            resp = self.req.get(test_url)
            if resp:
                if "root:x:" in resp.text or "bin/bash" in resp.text or "<?php" in resp.text:
                    return True, f"lfi_detected ({payload})"
        return False, None
    
    def detect_xxe(self, endpoint, method="post", data_key=None):
        """Deteksi XXE dengan mengirim XML payload"""
        if not self.cfg['scan']['detect_xxe']:
            return False, None
        for payload in xxe_payloads.XXE_PAYLOADS:
            headers = {'Content-Type': 'application/xml'}
            if method.lower() == 'post':
                resp = self.req.post(f"{self.target}/{endpoint}", data=payload, headers=headers)
            else:
                # GET dengan parameter XML? jarang, skip
                continue
            if resp and ("root:" in resp.text or "etc/passwd" in resp.text):
                return True, "xxe_detected"
        return False, None
