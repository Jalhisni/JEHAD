import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import jehad_core as c

SAMPLE = '''<?xml version="1.0"?><nmaprun><host><status state="up"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2" /></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" /></port>
<port protocol="tcp" portid="5432"><state state="closed"/></port>
</ports></host></nmaprun>'''

class CoreTests(unittest.TestCase):
    def test_ip_validation_prevents_shell_injection(self):
        for s in ("127.0.0.1; rm -rf /", "192.168.1.0/24", "example.com", ""):
            with self.assertRaises(ValueError): c.parse_ip(s)
    def test_quarantine_refuses_local_and_multicast(self):
        for s in ("127.0.0.1", "::1", "224.0.0.1", "0.0.0.0", "255.255.255.255"):
            with self.assertRaises(ValueError): c.parse_ip(s, for_firewall=True)
    def test_scan_port_observation_not_cve(self):
        out = c.parse_nmap_xml(SAMPLE, "192.168.56.101", "Quick")
        self.assertEqual(out["open_count"], 2)
        self.assertEqual(out["open_ports"][0]["version"], "OpenSSH 9.2")
        self.assertTrue(all("not" in p["evidence"].lower() for p in out["open_ports"]))
        self.assertFalse(any("EternalBlue" in str(p) for p in out["open_ports"]))
    def test_preview_is_nonmutating(self):
        txt = " ".join(c.quarantine_preview("192.168.56.100"))
        self.assertIn("deny in", txt)
        self.assertIn("deny out", txt)
    def test_tagged_undo_targets_only_exact_ids(self):
        status = "Status: active\n[ 1] Anywhere DENY IN 10.0.0.2 # JEHAD_AABBCCDD_IN\n[ 2] Anywhere DENY IN 10.0.0.2 # OTHER\n[ 3] 10.0.0.2 DENY OUT Anywhere # JEHAD_AABBCCDD_OUT"
        self.assertEqual(c._numbered_tagged_rules(status, ["JEHAD_AABBCCDD_IN", "JEHAD_AABBCCDD_OUT"]), [3, 1])
    def test_standard_nmap_xml_doctype(self):
        # Real Nmap -oX - output includes this benign document type header.
        sample = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                  '<!DOCTYPE nmaprun>\n'
                  '<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>\n'
                  + SAMPLE[SAMPLE.index('<nmaprun'):])
        out = c.parse_nmap_xml(sample, "127.0.0.1", "Quick")
        self.assertEqual(out['open_count'], 2)

    def test_reject_xml_entity(self):
        payload = '<!DOCTYPE nmaprun [<!ENTITY attack "value">]><nmaprun />'
        with self.assertRaises(ValueError):
            c.parse_nmap_xml(payload, "127.0.0.1", "Quick")

    def test_prevent_xml_doctype(self):
        with self.assertRaises(ValueError):
            c.parse_nmap_xml("<!DOCTYPE foo><nmaprun></nmaprun>", "1.2.3.4", "Quick")

if __name__ == '__main__': unittest.main()

from unittest.mock import patch

class FirewallMockTests(unittest.TestCase):
    def test_apply_and_undo_tagged_rules_using_mock(self):
        record_list = []
        live_rules = []
        def fake_ufw(args, timeout=45):
            if args[0] == 'status':
                return 'Status: active\n' + '\n'.join(
                    f'[ {i}] Anywhere DENY {rule[3].upper()} Anywhere # {rule[-1]}'
                    for i, rule in enumerate(live_rules, start=1))
            if args[0] == 'insert':
                live_rules.insert(0, args)
                return 'Rule added'
            if args[0] == '--force' and args[1] == 'delete':
                live_rules.pop(int(args[2])-1)
                return 'Rule deleted'
            raise AssertionError(args)
        def save(data):
            record_list[:] = data
        with patch.object(c, 'run_ufw', side_effect=fake_ufw), \
             patch.object(c, 'read_quarantines', side_effect=lambda: record_list), \
             patch.object(c, '_save_state', side_effect=save), \
             patch.object(c, 'log_event', side_effect=lambda *args, **kwargs: None):
            applied = c.apply_quarantine('192.168.56.101')
            self.assertEqual(len(live_rules), 2)
            self.assertTrue(all(applied['tag'] in str(x) for x in live_rules))
            undone = c.undo_quarantine('192.168.56.101')
            self.assertEqual(undone['state'], 'undone')
            self.assertEqual(live_rules, [])
