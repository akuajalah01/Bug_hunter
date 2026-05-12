#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Bug Hunter - Main Entry Point
Author: akuajalah01
"""

import argparse
import sys
import os
import colorama
from colorama import Fore, Style

# Tambahkan path project ke sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.utils import load_config, setup_logger
from modules.sqli import SQLiModule
from modules.xxe import XXEModule
from modules.lfi import LFIModule
from modules.rce import RCEModule

colorama.init(autoreset=True)

BANNER = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄
║  ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
║  ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌
║  ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
║  ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌
║  ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌
║   ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌
║            ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
║   ▄▄▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄█░▌
║  ▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌
║   ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀         ▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀ 
║                                                               ║
║              ⚡ BUG HUNTER MULTI-EXPLOIT FRAMEWORK ⚡          ║
║                    Author: akuajalah01                        ║
║              For Educational & Authorized Testing Only         ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="Bug Hunter - Multi-Exploit Framework")
    parser.add_argument("-u", "--url", required=True, help="Target base URL (e.g., http://example.com/page.php)")
    parser.add_argument("--sqli-param", help="Parameter name to test SQL injection")
    parser.add_argument("--xxe-endpoint", help="Endpoint (e.g., api/xml) to test XXE")
    parser.add_argument("--lfi-param", help="Parameter name to test LFI")
    parser.add_argument("--rce-lfi-param", help="LFI parameter for RCE via log poisoning")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--auto", action="store_true", help="Auto-scan for common vulnerabilities")
    args = parser.parse_args()
    
    # Buat folder output jika belum ada
    os.makedirs("output", exist_ok=True)
    logger = setup_logger("main")
    logger.info(f"Target: {args.url}")
    
    if args.auto:
        logger.info("Starting auto-scan mode...")
        common_params = ["id", "page", "q", "file", "doc", "param", "cat", "view"]
        
        # SQLi
        for param in common_params:
            logger.debug(f"Testing SQLi on parameter: {param}")
            sqli = SQLiModule(args.url, args.proxy)
            result = sqli.run(param)
            if result and result.get("vulnerable"):
                print(f"{Fore.GREEN}[!] SQLi found on {param}: {result}{Style.RESET_ALL}")
        
        # LFI
        for param in common_params:
            lfi = LFIModule(args.url, args.proxy)
            result = lfi.run(param)
            if result and result.get("vulnerable"):
                print(f"{Fore.GREEN}[!] LFI found on {param}{Style.RESET_ALL}")
        
        # XXE (coba endpoint umum)
        common_endpoints = ["xml", "api/xml", "upload", "soap"]
        for ep in common_endpoints:
            xxe = XXEModule(args.url, args.proxy)
            result = xxe.run(ep)
            if result and result.get("vulnerable"):
                print(f"{Fore.GREEN}[!] XXE found on endpoint: {ep}{Style.RESET_ALL}")
    
    else:
        if args.sqli_param:
            sqli = SQLiModule(args.url, args.proxy)
            result = sqli.run(args.sqli_param)
            if result:
                print(f"{Fore.GREEN}[+] SQLi Result: {result}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] No SQLi vulnerability found on '{args.sqli_param}'{Style.RESET_ALL}")
        
        if args.xxe_endpoint:
            xxe = XXEModule(args.url, args.proxy)
            result = xxe.run(args.xxe_endpoint)
            if result:
                print(f"{Fore.GREEN}[+] XXE Result: {result}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] No XXE vulnerability found on '{args.xxe_endpoint}'{Style.RESET_ALL}")
        
        if args.lfi_param:
            lfi = LFIModule(args.url, args.proxy)
            result = lfi.run(args.lfi_param)
            if result and result.get("vulnerable"):
                print(f"{Fore.GREEN}[+] LFI vulnerable on '{args.lfi_param}'{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] No LFI vulnerability found on '{args.lfi_param}'{Style.RESET_ALL}")
        
        if args.rce_lfi_param:
            rce = RCEModule(args.url, args.proxy)
            result = rce.run(lfi_param=args.rce_lfi_param)
            if result and result.get("shell_url"):
                print(f"{Fore.GREEN}[+] RCE via LFI log poisoning: {result['shell_url']}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
