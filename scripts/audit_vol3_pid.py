"""Print Volatility 3 plugins exposing a PID or PIDs requirement.

Maintenance helper for the GUI's PID metadata. Run it with the app-owned
Python and pass the custom plugin directory as the first argument.
"""

import os
import sys

import volatility3.plugins
from volatility3 import framework
from volatility3.framework import constants


if len(sys.argv) > 1:
    volatility3.plugins.__path__ = [os.path.abspath(sys.argv[1])] + constants.PLUGINS_PATH

failures = framework.import_files(volatility3.plugins, True)
for name, plugin in sorted(framework.list_plugins().items()):
    for requirement in plugin.get_requirements():
        if requirement.name.lower() in {"pid", "pids"}:
            mode = "optional" if requirement.optional else "required"
            print(f"{name}\t{requirement.name}\t{mode}\t{type(requirement).__name__}")

if failures:
    print("LOAD_FAILURES\t" + ",".join(sorted(failures)), file=sys.stderr)
