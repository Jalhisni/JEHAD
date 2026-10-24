#!/usr/bin/env python3
"""JEHAD command-line interface. GUI: python JEHAD.py"""
import argparse
import json
import jehad_core as core


def main():
    p = argparse.ArgumentParser(description="JEHAD 2 — local connection monitor, authorized Nmap, local UFW containment")
    p.add_argument("-m", "--module", type=int, choices=range(1, 5), required=True,
                   help="1=local connections, 2=Nmap scan, 3=exposure guidance, 4=local UFW quarantine")
    p.add_argument("-t", "--target", default="", help="Single IP address")
    p.add_argument("--profile", choices=["Quick", "Standard", "Full TCP"], default="Quick")
    p.add_argument("--authorized", action="store_true", help="Affirm target scanning authorization (modules 2/3)")
    p.add_argument("--apply", action="store_true", help="Actually modify local UFW (module 4); default is preview")
    p.add_argument("--undo", action="store_true", help="Remove JEHAD-managed UFW rules (module 4)")
    p.add_argument("--confirm-local-firewall", action="store_true", help="Confirm awareness that LOCAL firewall rules will change")
    p.add_argument("--report", help="Save an HTML or JSON report")
    a = p.parse_args()
    try:
        if a.module == 1:
            rows = core.get_connections(a.target)
            print(json.dumps(rows, indent=2))
            if a.report:
                core.export_report(a.report, connections=rows)
        elif a.module in (2, 3):
            if not a.authorized:
                p.error("Scanning requires --authorized and an IP you own or are permitted to scan")
            scan = core.nmap_scan(a.target, a.profile, progress=lambda s: print(s, flush=True))
            print(json.dumps(scan, indent=2))
            if a.report:
                core.export_report(a.report, scan=scan)
        elif a.module == 4:
            ip = core.parse_ip(a.target, for_firewall=True)
            if not (a.apply or a.undo):
                print("\n".join(core.quarantine_preview(ip)))
                print("PREVIEW ONLY. No local UFW changes performed.")
                return
            if not a.confirm_local_firewall:
                p.error("Actual firewall changes require --confirm-local-firewall")
            record = core.undo_quarantine(ip) if a.undo else core.apply_quarantine(ip)
            print(json.dumps(record, indent=2))
    except (ValueError, RuntimeError, TimeoutError, core.ScanCancelled) as exc:
        p.exit(1, f"JEHAD error: {exc}\n")


if __name__ == "__main__":
    main()
