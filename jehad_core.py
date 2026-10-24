#!/usr/bin/env python3
"""JEHAD core: authorized network auditing and reversible LOCAL UFW rules.

No command is executed through a shell. A listening port is not a CVE finding.
"""
from __future__ import annotations

import datetime as dt
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET

APP_NAME = "JEHAD"
VERSION = "2.1.1"
DATA_DIR = Path.home() / ".local" / "share" / "jehad"
LOG_PATH = DATA_DIR / "events.jsonl"
STATE_PATH = DATA_DIR / "quarantine.json"

# Guidance only; it is NOT a database of detected vulnerabilities.
EXPOSURE_GUIDANCE = {
    21: ("Review", "FTP may expose credentials unless protected; verify TLS and access controls."),
    23: ("High", "Telnet typically carries plaintext credentials; replace with SSH."),
    80: ("Review", "Check whether this HTTP service redirects to HTTPS and is patched."),
    135: ("Review", "Restrict RPC to approved management networks."),
    139: ("Review", "Legacy NetBIOS exposure; restrict to trusted segments."),
    445: ("Review", "SMB exposure; restrict access and confirm patch/configuration status."),
    3389: ("Review", "RDP exposure; enforce VPN/MFA, patching and allowlists."),
    3306: ("Review", "Database port exposed; verify binding, auth and network ACLs."),
    5432: ("Review", "Database port exposed; verify binding, auth and network ACLs."),
    6379: ("Review", "Redis exposure; require authentication and restrict network access."),
}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def ensure_data_dir():
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)


def log_event(action: str, result: str, **details):
    ensure_data_dir()
    row = {"timestamp_utc": now_iso(), "action": action, "result": result, **details}
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


def read_events(limit=500):
    if not LOG_PATH.exists():
        return []
    rows = []
    for line in LOG_PATH.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return rows


def parse_ip(text: str, for_firewall=False) -> str:
    value = text.strip()
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Enter exactly one valid IPv4/IPv6 address, not a range or hostname.") from exc
    if for_firewall and (address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local or
                         str(address) == "255.255.255.255"):
        raise ValueError("Refusing to block loopback, multicast, link-local or unspecified addresses.")
    return str(address)


def get_connections(filter_ip=""):
    """List local machine connections. Restricted processes may not show their PID."""
    try:
        import psutil
    except ImportError as exc:
        raise RuntimeError("psutil missing. Install python3-psutil or pip install psutil.") from exc
    if filter_ip:
        filter_ip = parse_ip(filter_ip)
    rows = []
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied as exc:
        raise RuntimeError("Reading system-wide connections was denied by Linux; check local privileges.") from exc
    for c in connections:
        remote = c.raddr.ip if c.raddr else ""
        if filter_ip and remote != filter_ip:
            continue
        local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
        peer = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
        try:
            proc = psutil.Process(c.pid).name() if c.pid else "-"
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            proc = "Restricted"
        rows.append({"protocol": "TCP" if c.type == 1 else "UDP", "local": local,
                     "remote": peer, "state": c.status, "pid": c.pid or "-", "process": proc})
    rows.sort(key=lambda r: (r["process"], r["remote"], r["local"]))
    return rows


def parse_nmap_xml(xml_text: str, target: str, profile: str) -> dict:
    # Nmap's ordinary -oX output contains a benign `<!DOCTYPE nmaprun>` line.
    # ElementTree does not need it, so remove ONLY that exact declaration.
    # Disallow other DTDs and entity definitions to avoid unsafe XML input.
    if re.search(r"<!ENTITY\b", xml_text, flags=re.IGNORECASE):
        raise ValueError("Unexpected XML entity declaration in scanner output.")
    xml_text = re.sub(r"<!DOCTYPE\s+nmaprun\s*>", "", xml_text, flags=re.IGNORECASE)
    if re.search(r"<!DOCTYPE\b", xml_text, flags=re.IGNORECASE):
        raise ValueError("Unexpected XML document type in scanner output.")
    root = ET.fromstring(xml_text)
    if root.tag != "nmaprun":
        raise ValueError("Unexpected Nmap output format.")
    ports = []
    hosts_up = 0
    for host in root.findall("host"):
        if (host.find("status") is not None and host.find("status").get("state") == "up"):
            hosts_up += 1
        for item in host.findall("./ports/port"):
            state_element = item.find("state")
            state = state_element.get("state", "unknown") if state_element is not None else "unknown"
            if state != "open":
                continue
            service = item.find("service")
            attrs = service.attrib if service is not None else {}
            num = int(item.get("portid", "0"))
            service_name = attrs.get("name", "unknown").lower()
            if "telnet" in service_name:
                sev, note = "High", "Telnet usually transmits credentials in plaintext; disable or replace with SSH."
            elif service_name in ("ftp", "ftp-data"):
                sev, note = "Review", "FTP may expose credentials unless TLS is enforced; verify configuration."
            elif service_name in ("microsoft-ds", "netbios-ssn", "smb"):
                sev, note = "Review", "Restrict SMB/NetBIOS to trusted networks and verify patch status."
            elif "redis" in service_name:
                sev, note = "Review", "Verify Redis authentication, binding, ACL and network segmentation."
            else:
                sev, note = EXPOSURE_GUIDANCE.get(num, ("Info", "Open service; review patch level and access policy."))
                if num in EXPOSURE_GUIDANCE:
                    note = "Port-specific review suggestion (verify actual protocol): " + note
            version = " ".join(x for x in (attrs.get("product", ""), attrs.get("version", ""), attrs.get("extrainfo", "")) if x)
            ports.append({"port": num, "protocol": item.get("protocol", "tcp"), "state": state,
                          "service": attrs.get("name", "unknown"), "version": version,
                          "assessment": sev, "guidance": note,
                          "evidence": "Open port observed by Nmap; vulnerability is not automatically confirmed."})
    ports.sort(key=lambda p: p["port"])
    return {"type": "nmap", "timestamp_utc": now_iso(), "target": target, "profile": profile,
            "hosts_up": hosts_up, "open_ports": ports, "open_count": len(ports),
            "interpretation": "Port/service observations and exposure guidance only. CVEs are NOT verified."}


class ScanCancelled(Exception):
    pass


def nmap_scan(ip: str, profile: str = "Quick", cancel: threading.Event | None = None, progress=None) -> dict:
    ip = parse_ip(ip)
    if shutil.which("nmap") is None:
        raise RuntimeError("Nmap not found. Install it with: sudo apt install nmap")
    profiles = {
        "Quick": (["--top-ports", "100", "--version-light", "-T2", "--host-timeout", "180s"], 205),
        "Standard": (["--top-ports", "1000", "--version-light", "-T3", "--host-timeout", "360s"], 390),
        "Full TCP": (["-p-", "-T3", "--host-timeout", "900s"], 930),
    }
    if profile not in profiles:
        raise ValueError("Unknown scan profile")
    profile_args, timeout_sec = profiles[profile]
    command = ["nmap", "-sT", "-sV", "-n", "-Pn", "--max-retries", "1", "-oX", "-"]
    if ipaddress.ip_address(ip).version == 6:
        command.append("-6")
    command += profile_args + [ip]
    if progress:
        progress(f"Starting {profile} TCP scan for {ip}...")
    started = time.monotonic()
    # Temporary output files avoid a filled stdout pipe deadlocking large scans.
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as xml_out, \
         tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as err_out:
        proc = subprocess.Popen(command, text=True, stdout=xml_out, stderr=err_out)
        try:
            while proc.poll() is None:
                if cancel is not None and cancel.is_set():
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    raise ScanCancelled("Scan stopped by user")
                if time.monotonic() - started > timeout_sec:
                    proc.kill()
                    raise TimeoutError(f"Nmap exceeded the {timeout_sec}s safety timeout")
                time.sleep(0.25)
            xml_out.seek(0)
            err_out.seek(0)
            stdout, stderr = xml_out.read(), err_out.read()
            if proc.returncode:
                raise RuntimeError(f"Nmap returned {proc.returncode}: {stderr.strip()[:650]}")
            result = parse_nmap_xml(stdout, ip, profile)
            log_event("NMAP_SCAN", "SUCCESS", target=ip, profile=profile, open_ports=result["open_count"])
            return result
        except Exception as exc:
            log_event("NMAP_SCAN", "CANCELLED" if isinstance(exc, ScanCancelled) else "ERROR", target=ip, error=str(exc))
            raise
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


def _ufw_binary():
    path = shutil.which("ufw") or "/usr/sbin/ufw"
    if not Path(path).exists():
        raise RuntimeError("UFW not installed. Install with: sudo apt install ufw")
    return path


def run_ufw(args, timeout=45):
    """Run UFW on the local host; use cached terminal sudo authentication only."""
    command = [_ufw_binary(), *args]
    if os.geteuid() != 0:
        if shutil.which("sudo"):
            command = ["sudo", "-n", *command]
        else:
            raise RuntimeError("sudo is required for local firewall changes. Install sudo or run as root.")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("UFW authorization/operation timed out") from exc
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip()[:750]
        if "password is required" in message.lower() or "a password is required" in message.lower():
            raise RuntimeError("UFW needs administrator authorization. Run 'sudo -v' in the same terminal, then retry.")
        raise RuntimeError(message or f"UFW exited {result.returncode}")
    return result.stdout.strip()


def ufw_status():
    return run_ufw(["status", "numbered"])


def _require_active(status_text):
    if not re.search(r"(?im)^Status:\s+active\s*$", status_text):
        raise RuntimeError("UFW is INACTIVE. No rules applied. Review current firewall/SSH policies before manually enabling UFW.")


def _numbered_tagged_rules(status_text: str, tags: list[str]):
    found = []
    for line in status_text.splitlines():
        m = re.match(r"^\[\s*(\d+)\]\s+(.+)$", line.strip())
        if m and any(re.search(r"(?<![A-Za-z0-9_])" + re.escape(tag) + r"(?![A-Za-z0-9_])", m.group(2)) for tag in tags):
            found.append(int(m.group(1)))
    return sorted(set(found), reverse=True)


def _save_state(rows):
    ensure_data_dir()
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    os.replace(tmp, STATE_PATH)
    try:
        os.chmod(STATE_PATH, 0o600)
    except OSError:
        pass


def read_quarantines():
    if not STATE_PATH.exists():
        return []
    try:
        rows = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return rows if isinstance(rows, list) else []
    except (OSError, ValueError):
        return []


def quarantine_preview(ip):
    ip = parse_ip(ip, for_firewall=True)
    return [f"sudo ufw insert 1 deny in from {ip} to any comment JEHAD_<ID>_IN",
            f"sudo ufw insert 1 deny out from any to {ip} comment JEHAD_<ID>_OUT"]


def apply_quarantine(ip):
    """Restrict traffic TO/FROM ip ON THIS COMPUTER ONLY (not globally)."""
    ip = parse_ip(ip, for_firewall=True)
    _require_active(ufw_status())
    tag = f"JEHAD_{uuid.uuid4().hex[:8].upper()}"
    tags = [f"{tag}_IN", f"{tag}_OUT"]
    # Put managed deny rules first so a broad pre-existing allow is less likely
    # to take precedence. These rules do NOT guarantee existing sessions stop.
    rules = [["insert", "1", "deny", "in", "from", ip, "to", "any", "comment", tags[0]],
             ["insert", "1", "deny", "out", "from", "any", "to", ip, "comment", tags[1]]]
    applied = []
    try:
        for rule, label in zip(rules, tags):
            run_ufw(rule)
            # Do not blindly assume command success; require the unique tag in live UFW listing.
            _require_active(ufw_status())
            applied.append(label)
            status = ufw_status()
            if len(_numbered_tagged_rules(status, [label])) != 1:
                raise RuntimeError(f"Could not confirm exact rule {label} in live UFW status")
        record = {"ip": ip, "tag": tag, "created_at_utc": now_iso(), "state": "applied"}
        rows = read_quarantines()
        rows.append(record)
        _save_state(rows)
        log_event("UFW_QUARANTINE", "SUCCESS", target=ip, rule_tag=tag)
        return record
    except Exception as exc:
        # Attempt to remove ONLY rules tagged by this run. Report a partial rollback explicitly.
        rollback_error = None
        try:
            status = ufw_status()
            for n in _numbered_tagged_rules(status, applied):
                run_ufw(["--force", "delete", str(n)])
        except Exception as cleanup_exc:
            rollback_error = str(cleanup_exc)
        log_event("UFW_QUARANTINE", "ERROR", target=ip, error=str(exc), rollback_error=rollback_error)
        if rollback_error:
            raise RuntimeError(f"{exc}; automatic cleanup FAILED: {rollback_error}. Inspect 'sudo ufw status numbered'.") from exc
        raise


def undo_quarantine(ip):
    ip = parse_ip(ip, for_firewall=True)
    rows = read_quarantines()
    matching = [r for r in rows if r.get("ip") == ip and r.get("state") == "applied"]
    if not matching:
        raise ValueError("No JEHAD-managed quarantine record for this IP; cannot remove unrelated rules.")
    record = matching[-1]
    tag = record["tag"]
    if not re.fullmatch(r"JEHAD_[0-9A-F]{8}", tag):
        raise ValueError("Stored quarantine tag is invalid; refusing to remove rules.")
    _require_active(ufw_status())
    status = ufw_status()
    numbers = _numbered_tagged_rules(status, [tag + "_IN", tag + "_OUT"])
    if not numbers:
        raise RuntimeError("No matching JEHAD firewall rules found. Inspect UFW before changing stored state.")
    for number in numbers:
        run_ufw(["--force", "delete", str(number)])
    still = _numbered_tagged_rules(ufw_status(), [tag + "_IN", tag + "_OUT"])
    if still:
        raise RuntimeError("Some JEHAD rules remain; review 'ufw status numbered' manually.")
    record["state"] = "undone"
    record["undone_at_utc"] = now_iso()
    _save_state(rows)
    log_event("UFW_QUARANTINE_UNDO", "SUCCESS", target=ip, rule_tag=tag)
    return record


def make_report(scan=None, connections=None):
    return {"tool": APP_NAME, "version": VERSION, "generated_utc": now_iso(),
            "scan": scan, "local_connections": connections or [], "audit_events": read_events(),
            "limitations": ["An open port does not prove vulnerability or CVE exposure.",
                            "Connections are local to the machine running JEHAD.",
                            "UFW rules affect only the firewall of this machine, not a remote host globally.",
                            "UFW may not interrupt pre-existing tracked connections."]}


def export_report(path, scan=None, connections=None):
    data = make_report(scan, connections)
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    if file.suffix.lower() == ".json":
        file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return file
    if file.suffix.lower() != ".html":
        raise ValueError("Use an .html or .json filename")
    esc = lambda x: html.escape(str(x if x is not None else ""), quote=True)
    scan_data = scan or {}
    port_rows = "".join("<tr>" + "".join(f"<td>{esc(p.get(k,''))}</td>" for k in ("port", "protocol", "service", "version", "assessment", "guidance")) + "</tr>" for p in scan_data.get("open_ports", []))
    connection_rows = "".join("<tr>" + "".join(f"<td>{esc(c.get(k,''))}</td>" for k in ("protocol", "local", "remote", "state", "pid", "process")) + "</tr>" for c in (connections or []))
    event_rows = "".join("<tr>" + "".join(f"<td>{esc(e.get(k,''))}</td>" for k in ("timestamp_utc", "action", "result")) + "</tr>" for e in data["audit_events"])
    content = f'''<!doctype html><html lang="en"><meta charset="utf-8"><title>JEHAD Security Report</title>
<style>body{{font:14px system-ui,sans-serif;max-width:1100px;margin:36px auto;color:#143333;padding:0 22px}}h1{{color:#076c52}}h2{{color:#0d7361;margin-top:34px}}small{{color:#64748b}}table{{width:100%;border-collapse:collapse;font-size:12px;word-break:break-word}}th,td{{padding:9px;border-bottom:1px solid #d9e9e4;text-align:left}}th{{background:#e5f5ef}}.alert{{padding:12px;background:#fff6d5;border-left:4px solid #ac8507}}</style>
<h1>JEHAD — Security Auditing &amp; Incident Response</h1><small>Saudi-built · v{esc(VERSION)} · {esc(data['generated_utc'])}</small>
<p class="alert">Open ports and associated guidance are NOT confirmed vulnerabilities. Use on authorized assets only.</p>
<h2>Port Audit</h2><p>Target: {esc(scan_data.get('target','No scan yet'))} · Profile: {esc(scan_data.get('profile','-'))} · Open ports: {esc(scan_data.get('open_count','-'))}</p>
<table><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th><th>Priority</th><th>Review guidance</th></tr></thead><tbody>{port_rows}</tbody></table>
<h2>Local Connections</h2><table><thead><tr><th>Proto</th><th>Local</th><th>Remote</th><th>State</th><th>PID</th><th>Process</th></tr></thead><tbody>{connection_rows}</tbody></table>
<h2>Audit Events</h2><table><thead><tr><th>UTC</th><th>Action</th><th>Result</th></tr></thead><tbody>{event_rows}</tbody></table>
<h2>Limitations</h2><ul>{''.join('<li>'+esc(x)+'</li>' for x in data['limitations'])}</ul>
<footer><small>JEHAD by Jehad Alhisni · Generated locally.</small></footer></html>'''
    file.write_text(content, encoding="utf-8")
    return file
