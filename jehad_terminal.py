#!/usr/bin/env python3
"""Terminal-only interactive JEHAD security auditing shell (Kali/Linux)."""
from __future__ import annotations

import cmd
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
import textwrap

import jehad_core as core

COLOR = sys.stdout.isatty() and not os.environ.get('NO_COLOR')


def paint(s, color='green'):
    colors = {'green': '38;5;48', 'teal': '38;5;43', 'gold': '38;5;221',
              'red': '38;5;203', 'muted': '38;5;245', 'white': '1;37'}
    return f'\033[{colors.get(color, "0")}m{s}\033[0m' if COLOR else str(s)


def ok(s): print(paint('[+] ', 'green') + str(s))
def note(s): print(paint('[*] ', 'teal') + str(s))
def warn(s): print(paint('[!] ', 'gold') + str(s))
def err(s): print(paint('[-] ', 'red') + str(s))


def banner():
    print(paint(r'''    ╔═════════════════════════════════════════════════════════╗
    ║                                                         ║
    ║       ██╗███████╗██╗  ██╗ █████╗ ██████╗               ║
    ║       ██║██╔════╝██║  ██║██╔══██╗██╔══██╗              ║
    ║       ██║█████╗  ███████║███████║██║  ██║              ║
    ║  ██   ██║██╔══╝  ██╔══██║██╔══██║██║  ██║              ║
    ║  ╚█████╔╝███████╗██║  ██║██║  ██║██████╔╝              ║
    ║   ╚════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝               ║
    ║                                                         ║
    ╚═════════════════════════════════════════════════════════╝''','green'))
    print('       ' + paint('SAUDI CYBER DEFENSE  |  SECURITY OPERATIONS', 'gold'))
    print('       ' + paint(f'JEHAD v{core.VERSION} Terminal Edition · Jehad Alhisni', 'teal'))
    print('       ' + paint('Authorized assets only • LOCAL firewall actions', 'muted'))
    print()


def as_words(arg):
    try:
        return shlex.split(arg)
    except ValueError as exc:
        raise ValueError(f'Invalid quoting: {exc}') from exc


def truncate(value, limit=22):
    value = str(value).replace('\n', ' ')
    return value if len(value) <= limit else value[:limit-1] + '…'


def table(headers, rows, caps=None):
    rows = [[str(x) for x in row] for row in rows]
    caps = caps or [26] * len(headers)
    widths = [min(caps[i], max(len(str(headers[i])), *(len(row[i]) for row in rows))) for i in range(len(headers))]
    widths = [max(4, x) for x in widths]
    fmt = '  '.join('{:<'+str(n)+'}' for n in widths)
    print(paint(fmt.format(*(truncate(h, widths[i]) for i,h in enumerate(headers))), 'teal'))
    print(paint('  '.join('─'*n for n in widths), 'muted'))
    for row in rows:
        print(fmt.format(*(truncate(value, widths[i]) for i,value in enumerate(row))))


class JehadShell(cmd.Cmd):
    intro = ''
    ruler = '─'
    def __init__(self):
        super().__init__()
        self.module = None
        self.target = ''
        self.profile = 'Quick'
        self.authorized = False
        self.last_scan = None
        self.last_connections = []
        self.refresh_prompt()

    def refresh_prompt(self):
        suffix = f'({self.module})' if self.module else ''
        self.prompt = paint('JEHAD', 'green') + paint(suffix, 'gold') + paint(' > ', 'teal')

    def emptyline(self): pass
    def default(self, line):
        err(f'Unknown command: {line.split()[0]}. Type help.')

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except KeyboardInterrupt:
            print(); warn('Cancelled. No scan results saved.')
        except (ValueError, RuntimeError, OSError, TimeoutError, core.ScanCancelled) as exc:
            err(exc)
        except Exception as exc:
            err(f'Unexpected error: {type(exc).__name__}: {exc}')

    def do_help(self, arg):
        """Show terminal commands."""
        if arg.strip():
            return super().do_help(arg)
        print(paint('\n  JEHAD TERMINAL COMMANDS', 'gold'))
        print('  help                         Show this help')
        print('  modules                      Show available modules')
        print('  use scanner                  Select a module (scanner/connections/exposure/quarantine/reports)')
        print('  show options                 Display selected module settings')
        print('  set target 192.168.56.101    Set an IP target')
        print('  set profile quick            Scan profile: quick, standard, full')
        print('  set authorized yes           Confirm permission to scan selected target')
        print('  run                          Run selected module')
        print('  back                         Return to main prompt')
        print('  connections [IP]             Local TCP/UDP sessions (optionally filter remote IP)')
        print('  scan <IP> [profile]          Authorized Nmap TCP service scan')
        print('  exposure                     Review LAST scan: exposure guidance, not CVE detection')
        print('  quarantine preview <IP>      Show LOCAL UFW changes without applying')
        print('  quarantine apply <IP>        Confirm, add and verify local UFW deny rules')
        print('  quarantine undo <IP>         Remove only JEHAD-managed UFW rules')
        print('  quarantine list              Show JEHAD-managed quarantine history')
        print('  quarantine status            Show LOCAL firewall status')
        print('  report [filename.html]       Export HTML/JSON findings and event log')
        print('  history                      Show recent audit events')
        print('  status                       Check dependencies and current session')
        print('  clear | banner | exit        Housekeeping\n')
        note('Only test IPs you own or are authorized to assess; UFW acts on THIS Kali machine.')

    def do_modules(self, arg):
        """List available modules."""
        table(['MODULE','PURPOSE'], [
            ['connections', 'Monitor this machine TCP/UDP sockets'],
            ['scanner', 'Real Nmap scan: ports, detected services, versions'],
            ['exposure', 'Review last scan; no automatic CVE confirmation'],
            ['quarantine', 'Preview/apply/undo local UFW restrictions'],
            ['reports', 'Generate local HTML/JSON audit report']], [16, 63])

    def do_use(self, arg):
        """use scanner|connections|exposure|quarantine|reports"""
        choice = arg.strip().lower()
        aliases = {'monitor':'connections', 'scan':'scanner', 'audit':'scanner', 'ufw':'quarantine', 'report':'reports'}
        choice = aliases.get(choice, choice)
        if choice not in ('connections', 'scanner','exposure','quarantine','reports'):
            err('Choose: connections | scanner | exposure | quarantine | reports')
            return
        self.module = choice
        self.refresh_prompt()
        ok(f'Module selected: {choice}. Type show options or run.')

    def do_back(self, arg):
        """Leave module."""
        self.module = None
        self.refresh_prompt()

    def do_show(self, arg):
        """show options | show modules"""
        if arg.strip().lower() == 'modules': return self.do_modules('')
        if arg.strip().lower() != 'options':
            err('Usage: show options'); return
        table(['OPTION','VALUE'],[
            ['MODULE', self.module or 'none'],
            ['TARGET', self.target or 'not set'],
            ['PROFILE', self.profile],
            ['AUTHORIZED', 'YES' if self.authorized else 'NO'],
            ['LAST SCAN', f'{self.last_scan["target"]} ({self.last_scan["open_count"]} open)' if self.last_scan else 'none'],
        ], [18,62])

    def do_set(self, arg):
        """set target <IP> | set profile quick|standard|full | set authorized yes|no"""
        words = as_words(arg)
        if len(words) != 2:
            err('Usage: set target 192.168.56.101 | set profile standard | set authorized yes');return
        key,val = words[0].lower(),words[1]
        if key == 'target':
            ip = core.parse_ip(val)
            self.target = ip
            self.authorized = False  # authorization is target-specific
            ok(f'TARGET = {ip}; authorization reset for new target')
        elif key == 'profile':
            self.profile = self._profile(val)
            ok('PROFILE = '+self.profile)
        elif key == 'authorized':
            if val.lower() not in ('yes','no'):
                raise ValueError('authorized must be yes or no')
            if val.lower() == 'yes':
                if not self.target:
                    raise ValueError('Set target first, then affirm authorization.')
                warn('Use only on networks you own or are explicitly permitted to assess.')
            self.authorized = (val.lower() == 'yes')
            ok(f'AUTHORIZED = {self.authorized}')
        else:
            err('Supported options: target, profile, authorized')

    @staticmethod
    def _profile(value):
        m = {'quick':'Quick','standard':'Standard','full':'Full TCP','full tcp':'Full TCP', 'full-tcp':'Full TCP'}
        try: return m[value.strip().lower()]
        except KeyError: raise ValueError('Profile must be quick, standard or full')

    def do_run(self, arg):
        """Execute selected module with current options."""
        if not self.module:
            err('Select a module using use scanner, use connections, ...');return
        if self.module == 'connections': return self.do_connections(self.target)
        if self.module == 'scanner': return self._scan(self.target, self.profile)
        if self.module == 'exposure': return self.do_exposure('')
        if self.module == 'quarantine':
            if not self.target: raise ValueError('Set a TARGET IP first.')
            return self.do_quarantine('preview '+self.target)
        if self.module == 'reports': return self.do_report('')

    def do_connections(self, arg):
        """Show local connections; optional remote peer IP filter."""
        words = as_words(arg)
        if len(words)>1: raise ValueError('Usage: connections [IP]')
        ip = words[0] if words else ''
        rows = core.get_connections(ip)
        self.last_connections = rows
        if not rows:
            warn('No matching LOCAL TCP/UDP connections. This does not probe a remote host.')
            return
        table(['PROTO', 'LOCAL', 'REMOTE','STATE','PID','PROCESS'],
              [[x[k] for k in ('protocol','local','remote','state','pid','process')] for x in rows[:70]],
              [6,29,29,14,7,22])
        ok(f'{len(rows)} local socket(s) listed'+(' (first 70 shown)' if len(rows)>70 else ''))
        core.log_event('LOCAL_CONNECTIONS','SUCCESS',filter_ip=ip,count=len(rows))

    def _scan(self, ip, profile):
        if not ip: raise ValueError('Set target first (set target <IP>) or scan <IP> [profile].')
        ip = core.parse_ip(ip)
        if not self.authorized or self.target != ip:
            warn(f'You are about to actively probe {ip}. Only scan systems you own or have written permission to test.')
            answer = input('  Type AUTHORIZED to continue: ').strip()
            if answer != 'AUTHORIZED':
                warn('Scan aborted without network probing.');return
        note(f'Launching {profile} TCP scan with Nmap for {ip}. Ctrl+C to cancel.')
        result = core.nmap_scan(ip, profile, progress=note)
        self.last_scan = result
        if not result['open_ports']:
            warn('No open TCP ports reported. Filtered/closed ports are not listed.')
        else:
            table(['PORT','SERVICE','VERSION','GUIDANCE'],[
                [str(p['port'])+'/'+p['protocol'], p['service'],p['version'] or '-',p['assessment']]
                for p in result['open_ports']],[10,18,35,12])
        ok(f'{result["open_count"]} OPEN TCP port(s) reported by Nmap. Target: {ip}')
        warn('A port or service alone does not prove an exploitable vulnerability. Type exposure for guidance.')

    def do_scan(self, arg):
        """scan <IP> [quick|standard|full]"""
        words = as_words(arg)
        if len(words) > 2: raise ValueError('Usage: scan 192.168.56.101 quick')
        ip = words[0] if words else self.target
        profile = self._profile(words[1]) if len(words)>1 else self.profile
        return self._scan(ip, profile)

    def do_exposure(self, arg):
        """Show conservative recommendations from the last real Nmap scan."""
        if self.last_scan is None:
            warn('No scan results. Run scan <IP> quick first.');return
        print(paint('EXPOSURE REVIEW — NOT CONFIRMED VULNERABILITIES','gold'))
        print('  Target:',self.last_scan['target'])
        for p in self.last_scan['open_ports']:
            print(f'\n  [{p["assessment"]}] TCP/{p["port"]}  {p["service"]}  {p["version"] or ""}')
            print('  '+ textwrap.fill(p['guidance'], width=96, subsequent_indent='  '))
        if not self.last_scan['open_ports']:
            warn('No open ports in the last scan.')
        else:
            ok(f'{self.last_scan["open_count"]} port(s) reviewed; NO CVEs asserted or verified.')

    def do_quarantine(self, arg):
        """quarantine preview|apply|undo <IP> | quarantine list|status"""
        words = as_words(arg)
        if not words:
            err('Usage: quarantine preview|apply|undo <IP> or quarantine status|list');return
        action = words[0].lower()
        if action == 'list' and len(words) == 1:
            rows = core.read_quarantines()
            if rows: table(['TARGET','TAG','STATE','CREATED (UTC)'],[
                [r.get('ip','-'),r.get('tag','-'),r.get('state','-'),r.get('created_at_utc','-')] for r in rows[-30:]], [40,25,10,27])
            else: warn('No JEHAD-managed quarantines in local state file.')
            return
        if action == 'status' and len(words) == 1:
            print(core.ufw_status()); return
        if action not in ('preview','apply','undo') or len(words)!=2:
            raise ValueError('Usage: quarantine preview|apply|undo <IP> | quarantine status|list')
        ip = core.parse_ip(words[1], for_firewall=True)
        if action == 'preview':
            print(paint('LOCAL FIREWALL PREVIEW: no changes applied','gold'))
            for x in core.quarantine_preview(ip): print('  '+x)
            warn('These affect THIS Kali host only. Existing sessions may continue; review SSH access and rule order.')
            return
        warn('This modifies LOCAL Kali UFW. It DOES NOT isolate the remote host globally.')
        warn('Do not do this over an SSH session you cannot recover locally.')
        challenge = ('BLOCK ' if action == 'apply' else 'UNDO ') + ip
        answer = input(f'  To continue, type exactly "{challenge}": ').strip()
        if answer != challenge:
            warn('Cancelled. No changes requested.');return
        if action == 'apply':
            r = core.apply_quarantine(ip)
            ok(f'JEHAD-managed UFW rules visible for {ip}. Tag: {r["tag"]}')
            warn('Verify effective packet behavior separately; existing connections may continue.')
        else:
            r = core.undo_quarantine(ip)
            ok(f'Removed JEHAD-managed rules for {ip}. Tag: {r["tag"]}')

    def do_report(self, arg):
        """Export HTML or JSON with scan, local connections and event history."""
        words = as_words(arg)
        if len(words)>1: raise ValueError('Usage: report [filename.html|filename.json]')
        if words: path=Path(words[0]).expanduser()
        else:
            ts=core.now_iso().replace(':','-').replace('+','_')
            path=Path.cwd()/'reports'/f'JEHAD_report_{ts}.html'
        saved = core.export_report(path, scan=self.last_scan, connections=self.last_connections)
        ok('Report created: '+str(saved.resolve()))
        warn('Reports may contain sensitive IP/process data. Review before sharing publicly.')

    def do_history(self, arg):
        """Recent local audit events."""
        events = core.read_events(20)
        if not events: warn('No recorded events yet.');return
        table(['UTC','ACTION','RESULT','TARGET'],[
            [x.get('timestamp_utc',''),x.get('action',''),x.get('result',''),x.get('target',x.get('filter_ip','-'))] for x in events], [27,25,12,40])

    def do_status(self, arg):
        """Check configured target and runtime dependencies."""
        for prog in ('nmap','ufw','sudo'):
            print(f'  {prog:8} '+ (paint('FOUND', 'green') if shutil.which(prog) else paint('NOT FOUND','red')))
        try: import psutil; print(f'  psutil   '+paint('FOUND', 'green'))
        except ImportError: print('  psutil   '+paint('NOT FOUND','red'))
        print('  Target  :',self.target or '(none)')
        print('  Profile :',self.profile)
        print('  Module  :',self.module or '(none)')
        print('  Last scan:',self.last_scan['target'] if self.last_scan else '(none)')

    def do_banner(self, arg): banner()

    def do_clear(self, arg):
        """Clear terminal."""
        print('\033[2J\033[H' if COLOR else '\n'*4, end='')

    def do_exit(self, arg):
        """Exit the tool."""
        print(paint('JEHAD session ended. Stay secure.', 'teal'))
        return True

    def do_quit(self, arg): return self.do_exit(arg)
    def do_EOF(self, arg): print(); return self.do_exit(arg)


def main():
    import argparse
    parser=argparse.ArgumentParser(description='JEHAD 2.1 terminal-only Kali security auditing and incident response')
    parser.add_argument('--no-banner',action='store_true',help='Skip ASCII banner')
    parser.add_argument('-c','--command',help='Run one JEHAD shell command (e.g. -c "connections")')
    args=parser.parse_args()
    if not args.no_banner: banner()
    shell=JehadShell()
    if args.command:
        shell.onecmd(args.command)
        return
    print('  Type '+paint('help','green')+' to see commands, or '+paint('modules','green')+' to list features.\n')
    try: shell.cmdloop()
    except KeyboardInterrupt: print('\n'); shell.do_exit('')


if __name__ == '__main__':
    main()
