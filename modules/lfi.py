from core.scanner import Scanner

class LFIModule:
    def __init__(self, target_url, proxy=None):
        self.scanner = Scanner(target_url, proxy)
    
    def run(self, param):
        is_vuln, _ = self.scanner.detect_lfi(param)
        return {"vulnerable": is_vuln}
