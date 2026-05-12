from core.scanner import Scanner
from core.exploit import Exploit

class XXEModule:
    def __init__(self, target_url, proxy=None):
        self.scanner = Scanner(target_url, proxy)
        self.exploit = Exploit(target_url, proxy)
    
    def run(self, endpoint):
        is_vuln, _ = self.scanner.detect_xxe(endpoint)
        if not is_vuln:
            return None
        content = self.exploit.xxe_read_file(endpoint)
        return {
            "vulnerable": True,
            "file_content_preview": content[:200] if content else None
        }
