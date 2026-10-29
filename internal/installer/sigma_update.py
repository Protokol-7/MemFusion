"""Update through Zircolite's API, propagating errors hidden by its CLI."""
import json
import logging
from pathlib import Path
from zircolite.rules import RulesUpdater

logging.basicConfig(level=logging.INFO)
updater = RulesUpdater(logger=logging.getLogger('sigma-update'))
try:
    updater.download()
    updater.unzip()
    candidates = list(Path(updater.tmpDir).rglob('rules_windows_generic.json'))
    if len(candidates) != 1:
        raise RuntimeError('Downloaded archive must contain one Windows generic ruleset')
    rules = json.loads(candidates[0].read_text(encoding='utf-8'))
    if not isinstance(rules, list) or not rules:
        raise RuntimeError('Downloaded Windows ruleset is empty or invalid')
    # Zircolite 4.1 replaced the legacy method with install(), which also
    # verifies the release manifest. Keep that verification in the update path.
    install = getattr(updater, 'install', None)
    if not callable(install):
        install = getattr(updater, 'checkIfNewerAndMove', None)
    if not callable(install):
        raise RuntimeError('Unsupported Zircolite rules updater API')
    install()
finally:
    updater.clean()
