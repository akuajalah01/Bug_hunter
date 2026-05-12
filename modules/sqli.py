from core.scanner import Scanner
from core.exploit import Exploit

class SQLiModule:
    def __init__(self, target_url, proxy=None):
        self.scanner = Scanner(target_url, proxy)
        self.exploit = Exploit(target_url, proxy)
    
    def run(self, param):
        is_vuln, tech = self.scanner.detect_sqli(param)
        if not is_vuln:
            return None
        db_name = self.exploit.sqli_extract_data(param, tech)
        shell_url = self.exploit.rce_via_sqli_outfile(param)
        return {
            "vulnerable": True,
            "technique": tech,
            "database": db_name,
            "shell_url": shell_url
        }
