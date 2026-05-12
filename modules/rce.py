from core.exploit import Exploit

class RCEModule:
    def __init__(self, target_url, proxy=None):
        self.exploit = Exploit(target_url, proxy)
    
    def run(self, lfi_param=None, sqli_param=None):
        if lfi_param:
            shell_url = self.exploit.lfi_to_rce(lfi_param)
            return {"vulnerable": shell_url is not None, "shell_url": shell_url}
        elif sqli_param:
            shell_url = self.exploit.rce_via_sqli_outfile(sqli_param)
            return {"vulnerable": shell_url is not None, "shell_url": shell_url}
        return None
