#!/usr/bin/env python3
import argparse
import sys
import os
from core.utils import load_config, setup_logger
from modules.sqli import SQLiModule
from modules.xxe import XXEModule
from modules.lfi import LFIModule
from modules.rce import RCEModule

def main():
    parser = argparse.ArgumentParser(description="Bug Hunter Multi-Exploit Framework")
    parser.add_argument("-u", "--url", required=True, help="Target base URL (e.g., http://example.com/page.php)")
    parser.add_argument("--sqli-param", help="Parameter name to test SQL injection")
    parser.add_argument("--xxe-endpoint", help="Endpoint (e.g., api/xml) to test XXE")
    parser.add_argument("--lfi-param", help="Parameter name to test LFI")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--auto", action="store_true", help="Auto-scan for all vulnerabilities")
    args = parser.parse_args()
    
    # Setup output dir
    os.makedirs("output", exist_ok=True)
    logger = setup_logger("main")
    
    if args.auto:
        logger.info(f"Auto scanning target: {args.url}")
        # Auto detect parameter dari form? Tidak, demo saja
        # Contoh manual: coba parameter common
        common_params = ["id", "page", "q", "file", "doc", "param"]
        for param in common_params:
            print(f"\n[*] Testing parameter: {param}")
            sqli = SQLiModule(args.url, args.proxy)
            res = sqli.run(param)
            if res:
                print(f"[!] SQLi found on {param}: {res}")
        
        # XXE
        xxe = XXEModule(args.url, args.proxy)
        res = xxe.run("xml")
        if res:
            print(f"[!] XXE found: {res}")
        
        # LFI
        lfi = LFIModule(args.url, args.proxy)
        for param in common_params:
            res = lfi.run(param)
            if res and res['vulnerable']:
                print(f"[!] LFI found on {param}")
    
    else:
        if args.sqli_param:
            sqli = SQLiModule(args.url, args.proxy)
            result = sqli.run(args.sqli_param)
            if result:
                print(f"[+] SQLi: {result}")
            else:
                print("[-] No SQLi found")
        
        if args.xxe_endpoint:
            xxe = XXEModule(args.url, args.proxy)
            result = xxe.run(args.xxe_endpoint)
            if result:
                print(f"[+] XXE: {result}")
            else:
                print("[-] No XXE")
        
        if args.lfi_param:
            lfi = LFIModule(args.url, args.proxy)
            result = lfi.run(args.lfi_param)
            if result and result['vulnerable']:
                print("[+] LFI vulnerable")
            else:
                print("[-] No LFI")

if __name__ == "__main__":
    main()
