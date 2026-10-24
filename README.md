# JEHAD v2.1.1 — Security Auditing & Incident Response (Terminal Edition)

**JEHAD** is a **Kali/Linux, terminal-only** cybersecurity auditing utility by **Jehad Alhisni**. The interface uses an interactive console (`JEHAD >`) similar in workflow to common security tooling: select a module, configure it, and run it. It **does not use PyQt6 or open graphical windows**.

## Modules

| Module | Real function | Limits |
|---|---|---|
| `connections` | Show local TCP/UDP sockets, PIDs and processes using `psutil` | Local Kali host only; some PIDs require elevated privileges |
| `scanner` | Run Nmap TCP scans with quick, standard and full-port presets; parse real XML service/version data | You must be explicitly authorized; results depend on network/firewall conditions |
| `exposure` | Show security review guidance associated with actually observed open ports/services | **Does not prove vulnerabilities or CVEs** |
| `quarantine` | Preview, insert, verify, list and undo tagged UFW rules for one IP address | Changes **local Kali host** firewall only; an existing session may persist; UFW must already be active |
| `reports` | Save HTML or JSON report with observed scan results, local sessions and event history | Review reports for sensitive data before sharing |

## Install and run on Kali Linux

Save `JEHAD_Terminal_v2.1.zip` to the Kali Desktop. Use exactly:

```bash
cd ~/Desktop
unzip -o JEHAD_Terminal_v2.1.zip
cd JEHAD_Terminal_v2.1
sudo apt update
sudo apt install -y python3-psutil nmap ufw
python3 JEHAD.py
```

No `pip install PyQt6` is needed. The console uses built-in Python libraries plus the `python3-psutil` package. If the ZIP is inside Downloads, change the `unzip` path accordingly.

### Optional: install a global `jehad` terminal command

From inside the extracted project folder:

```bash
bash install.sh
jehad
```

If `jehad` isn't found, run `export PATH="$HOME/.local/bin:$PATH"` and try again. The installer links to this folder; do not move/delete it afterward. No root privileges are needed for installation.

## Interactive example

```text
JEHAD > help
JEHAD > modules
JEHAD > use scanner
JEHAD(scanner) > set target 192.168.56.101
JEHAD(scanner) > set profile quick
JEHAD(scanner) > set authorized yes
JEHAD(scanner) > show options
JEHAD(scanner) > run
JEHAD(scanner) > exposure
JEHAD(scanner) > report reports/lab01.html
JEHAD(scanner) > back
JEHAD > connections
JEHAD > quarantine preview 192.168.56.101
JEHAD > exit
```

> `set authorized yes` is a declaration that you own the target or have express permission to scan it. Change the target IP to the authorized target in your own lab. `quick` tests 100 common TCP ports, `standard` 1000 common TCP ports, and `full` all 65,535 TCP ports. These are **not UDP scans**.

### Standalone commands

```bash
python3 JEHAD.py -c 'connections'
python3 JEHAD.py -c 'quarantine preview 192.168.56.101'
# Previous scripted CLI flags remain supported:
python3 JEHAD.py -m 2 -t 192.168.56.101 --profile Quick --authorized
```

## Local UFW management

**By default only `quarantine preview` is non-mutating.** To apply real local rules:

1. Run `sudo ufw status numbered` to inspect existing rules and determine whether UFW is active; **do not enable/reset UFW blindly**, especially on a remote SSH host.
2. In your same terminal, run `sudo -v` to cache administrator authorization.
3. From JEHAD, run `quarantine preview <IP>` first.
4. If safe, run `quarantine apply <IP>` and type the full confirmation phrase shown.
5. To reverse, run `quarantine undo <IP>` and type the full confirmation phrase. It will only attempt to delete JEHAD-tagged rules recorded in its own state.

JEHAD confirms the UFW rules appear in status, **not** that all network traffic is immediately stopped. Netfilter state, prior rules, routing and existing connections can affect outcomes. Changes are to the local Linux machine, never to the remote device's firewall. UFW changes are intentionally disabled when the firewall is inactive.

Local audit files: `~/.local/share/jehad/events.jsonl` and `~/.local/share/jehad/quarantine.json`.

## Security and accuracy

- The tool does not invoke `shell=True` for user input, and rejects hostnames/ranges for target operations.
- Open ports, potential risks and vulnerabilities are **different** concepts. JEHAD does not run exploit checks or authenticate CVEs.
- Use on networks/systems you own or have explicit written authorization to test.
- Keep full Nmap and UFW testing to disposable lab VMs before using any production system.
- Real firewall changes may interrupt access; don't run over a remote session without console recovery.
- Do not publish private IP/process data in public GitHub issues/reports.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Tests use sample Nmap XML and mocked firewall calls. They **do not** prove real-world scan or firewall behavior on your Kali host.

**Developer:** Jehad Alhisni  
**Identity:** Saudi cyber defense branding 🇸🇦  
**License:** No license granted unless a LICENSE file is added.

## v2.1.1 fix

Normal Nmap XML includes `<!DOCTYPE nmaprun>`. Earlier versions mistakenly rejected it with an error about unexpected XML declarations. v2.1.1 accepts Nmap's standard declaration while rejecting arbitrary document types and XML entities.

If you already have `~/Desktop/JEHAD_Terminal_v2.1`, extract the v2.1.1 fix ZIP from your Desktop using `unzip -o JEHAD_Terminal_v2.1.1_Fix.zip`, then run `cd JEHAD_Terminal_v2.1 && python3 JEHAD.py`.
