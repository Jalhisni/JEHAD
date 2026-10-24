import contextlib
from io import StringIO
from unittest import TestCase
from unittest.mock import patch
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from jehad_terminal import JehadShell
import jehad_core as core

class TerminalTests(TestCase):
    def setUp(self):
        self.shell = JehadShell()

    def output(self, command):
        buffer = StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell.onecmd(command)
        return buffer.getvalue()

    def test_modules_and_target_configuration(self):
        self.assertIn('scanner', self.output('modules'))
        self.output('use scanner')
        self.output('set target 192.168.56.101')
        self.output('set authorized yes')
        self.assertEqual(self.shell.target, '192.168.56.101')
        self.assertTrue(self.shell.authorized)
        self.output('set target 192.168.56.102')
        self.assertFalse(self.shell.authorized)

    def test_quarantine_preview_never_modifies_rules(self):
        with patch.object(core, 'run_ufw', side_effect=AssertionError('cannot modify UFW')):
            result = self.output('quarantine preview 192.168.56.101')
        self.assertIn('no changes applied', result)
        self.assertIn('insert 1 deny', result)

    def test_exposure_no_unfounded_cve(self):
        data = core.parse_nmap_xml('''<nmaprun><host><status state="up"/><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port></ports></host></nmaprun>''', '192.168.56.101','Quick')
        self.shell.last_scan = data
        result = self.output('exposure')
        self.assertIn('NO CVEs', result)
        self.assertNotIn('EternalBlue',result)

    def test_scan_requires_authorization(self):
        with patch.object(core, 'nmap_scan',side_effect=AssertionError('must not scan')):
            with patch('builtins.input',return_value='no'):
                output = self.output('scan 192.168.56.101 quick')
        self.assertIn('aborted', output)

    def test_scan_uses_authorized_nmap_results(self):
        sample = core.parse_nmap_xml('<nmaprun><host><status state="up"/><ports/></host></nmaprun>', '192.168.56.101','Quick')
        self.output('set target 192.168.56.101')
        self.output('set authorized yes')
        with patch.object(core,'nmap_scan',return_value=sample) as scan:
            self.assertIn('No open TCP ports',self.output('scan 192.168.56.101 quick'))
        scan.assert_called_once()
