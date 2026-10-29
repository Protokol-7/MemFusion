"""Offline regression tests; no installed tools or rules are modified."""
import json
import runpy
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


class SigmaUpdateTests(unittest.TestCase):
    def execute(self, mode, api='legacy'):
        with tempfile.TemporaryDirectory() as temp:
            state = {'moved': False, 'cleaned': False}

            class Updater:
                def __init__(self, logger):
                    self.tmpDir = temp

                def download(self):
                    if mode == 'network-error':
                        raise ConnectionError('offline')

                def unzip(self):
                    data = [] if mode == 'empty' else [{'title': 'test rule'}]
                    Path(temp, 'rules_windows_generic.json').write_text(json.dumps(data))

                def checkIfNewerAndMove(self):
                    if mode == 'install-error':
                        raise RuntimeError('manifest checksum mismatch')
                    state['moved'] = True

                def clean(self):
                    state['cleaned'] = True

            if api == 'current':
                Updater.install = Updater.checkIfNewerAndMove
                del Updater.checkIfNewerAndMove
            elif api == 'unknown':
                del Updater.checkIfNewerAndMove

            rules = types.ModuleType('zircolite.rules')
            rules.RulesUpdater = Updater
            with patch.dict(sys.modules, {'zircolite': types.ModuleType('zircolite'), 'zircolite.rules': rules}):
                try:
                    runpy.run_path(str(Path(__file__).with_name('sigma_update.py')))
                except (ConnectionError, RuntimeError):
                    state['failed'] = True
            return state

    def test_download_failure_propagates_without_replacing_rules(self):
        self.assertEqual(self.execute('network-error'), {'moved': False, 'cleaned': True, 'failed': True})

    def test_empty_download_preserves_existing_rules(self):
        self.assertEqual(self.execute('empty'), {'moved': False, 'cleaned': True, 'failed': True})

    def test_valid_download_installs_rules(self):
        self.assertEqual(self.execute('valid'), {'moved': True, 'cleaned': True})

    def test_current_api_installs_rules(self):
        self.assertEqual(self.execute('valid', 'current'), {'moved': True, 'cleaned': True})

    def test_manifest_failure_propagates(self):
        self.assertEqual(self.execute('install-error', 'current'), {'moved': False, 'cleaned': True, 'failed': True})

    def test_unknown_api_fails_and_cleans_up(self):
        self.assertEqual(self.execute('valid', 'unknown'), {'moved': False, 'cleaned': True, 'failed': True})


if __name__ == '__main__':
    unittest.main()
