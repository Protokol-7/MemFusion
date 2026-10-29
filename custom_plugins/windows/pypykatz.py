#
# Author:
#  Tamas Jos (@skelsec)
#  Leron Gray (@daddycocoaman)
#
# Updated version of the pypykatz plugin for Volatility 3


import logging
from typing import List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist

from pypykatz.pypykatz import pypykatz as pparser

vollog = logging.getLogger(__name__)


class pypykatz(interfaces.plugins.PluginInterface):

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # Patched for memforensics-gui: this vendored copy declared the
            # pre-3.x requirement pair (primary + nt_symbols), but pypykatz's
            # own go_volatility3() parser reads self.config["kernel"], so the
            # plugin failed with KeyError: 'kernel'. A ModuleRequirement named
            # "kernel" is what the modern framework and pypykatz both expect.
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(3, 0, 1)
            ),
        ]

    def run(self):
        return pparser.go_volatility3(self)