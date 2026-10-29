#!/usr/bin/env python3
"""Adapt vendored community plugins to the installed Volatility 3 API.

Why this exists
---------------
Most community plugins were written against Volatility 3 ~2.0-2.5. Since then
several core plugins had **major** version bumps that changed both their
declared version and their call signature. Two things then break:

1. ``PluginRequirement(..., version=(2, 0, 0))`` no longer matches, and vol3
   refuses to run the plugin at all:

       Unsatisfied requirement plugins.CobaltStrike.pslist:
       Version 2.0.0 dependency on volatility3.plugins.windows.pslist.PsList unmet

2. The classmethods those plugins call were reworked from taking
   ``layer_name`` + ``symbol_table`` to a single ``kernel_module_name``:

       PsList.list_processes(context, layer_name, symbol_table, filter_func)
       ->  PsList.list_processes(context, kernel_module_name, filter_func)

Fixing (1) without (2) turns a clean refusal into a TypeError at runtime, so
both are done together.

This is a script rather than a one-off edit because vol3 will do this again:
re-run it after upgrading Volatility 3, then re-test the plugins.

Usage:
    python3 scripts/patch_plugins_for_vol3.py [--check] [plugin_dir ...]

    --check   report what would change without writing (exit 1 if changes needed)
"""

from __future__ import annotations

import argparse
import importlib
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_DIRS = [REPO / "custom_plugins"]

# Core plugins the vendored code depends on, as module path -> import path.
CORE_PLUGINS = {
    "pslist.PsList": "volatility3.plugins.windows.pslist",
    "filescan.FileScan": "volatility3.plugins.windows.filescan",
    "vadyarascan.VadYaraScan": "volatility3.plugins.windows.vadyarascan",
    "info.Info": "volatility3.plugins.windows.info",
    "hivelist.HiveList": "volatility3.plugins.windows.registry.hivelist",
    "printkey.PrintKey": "volatility3.plugins.windows.registry.printkey",
    "poolscanner.PoolScanner": "volatility3.plugins.windows.poolscanner",
    "pedump.PEDump": "volatility3.plugins.windows.pedump",
    "dumpfiles.DumpFiles": "volatility3.plugins.windows.dumpfiles",
    "lsmod.Lsmod": "volatility3.plugins.linux.lsmod",
    "vadinfo.VadInfo": "volatility3.plugins.windows.vadinfo",
    "modules.Modules": "volatility3.plugins.windows.modules",
    "svcscan.SvcScan": "volatility3.plugins.windows.svcscan",
    "handles.Handles": "volatility3.plugins.windows.handles",
    "cmdline.CmdLine": "volatility3.plugins.windows.cmdline",
    "dlllist.DllList": "volatility3.plugins.windows.dlllist",
}

# Modules that exist under more than one OS namespace with *different*
# versions, so a bare "pslist.PsList" reference is ambiguous and must be
# resolved from the importing file (windows 3.0.1 vs linux 4.1.1).
AMBIGUOUS_PLUGINS = {
    "pslist.PsList": [
        "volatility3.plugins.windows.pslist",
        "volatility3.plugins.linux.pslist",
    ],
    "pstree.PsTree": [
        "volatility3.plugins.windows.pstree",
        "volatility3.plugins.linux.pstree",
    ],
}


def installed_versions() -> dict[str, tuple[int, int, int]]:
    """Read each core plugin's _version straight from the installed vol3.

    Entries are recorded twice: under the bare "module.Class" key, and under
    "<namespace>.module.Class" so callers can disambiguate the modules that
    exist under both windows/ and linux/ with different versions.
    """
    versions: dict[str, tuple[int, int, int]] = {}

    def record(name: str, module_path: str) -> None:
        cls_name = name.split(".", 1)[1]
        try:
            module = importlib.import_module(module_path)
            version = tuple(getattr(getattr(module, cls_name), "_version"))
        except Exception:
            return  # not present in this vol3; leave its requirement alone
        versions.setdefault(name, version)
        for ns in ("windows", "linux", "mac"):
            if f".{ns}." in module_path:
                versions[f"{ns}.{name}"] = version
                break

    for name, module_path in CORE_PLUGINS.items():
        record(name, module_path)
    for name, module_paths in AMBIGUOUS_PLUGINS.items():
        for module_path in module_paths:
            record(name, module_path)
    return versions


# --- rewrite rules ---------------------------------------------------------

# Keyword form spanning two lines, any spacing/indentation:
#     layer_name = kernel.layer_name,
#     symbol_table = kernel.symbol_table_name,
KWARG_PAIR = re.compile(
    r"""(?P<indent>[ \t]*)layer_name\s*=\s*\w+\.layer_name\s*,\s*\n
        [ \t]*symbol_table(?:_name)?\s*=\s*\w+\.symbol_table_name\s*,""",
    re.VERBOSE,
)

# Positional form:
#     scan_files(self.context, kernel.layer_name, kernel.symbol_table_name)
# possibly split across lines. The method name is captured because **not every
# API migrated**: VadInfo.protect_values still takes (context, layer_name,
# symbol_table) in 2.28. Rewriting those too collapses a correct 3-arg call
# into a broken 2-arg one — which is exactly what an earlier, method-blind
# version of this script did to bitwardendump and notepad.
POSITIONAL_PAIR = re.compile(
    r"(?P<method>\w+)(?P<head>\(\s*(?:\w+\.)?context\s*,\s*\n?\s*)"
    r"\w+\.layer_name\s*,\s*\n?\s*\w+\.symbol_table_name"
)


def migrated_methods() -> set[str]:
    """Names of core classmethods whose signature now takes kernel_module_name.

    Determined by inspecting the *installed* vol3 rather than assumed, so the
    script stays correct as more APIs migrate (or don't).
    """
    import inspect

    migrated: set[str] = set()
    seen_modules = set(CORE_PLUGINS.values())
    for paths in AMBIGUOUS_PLUGINS.values():
        seen_modules.update(paths)
    seen_modules.add("volatility3.plugins.windows.vadinfo")

    for module_path in seen_modules:
        try:
            module = importlib.import_module(module_path)
        except Exception:
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            for name, member in inspect.getmembers(obj):
                if name.startswith("_") or not callable(member):
                    continue
                try:
                    params = inspect.signature(member).parameters
                except (TypeError, ValueError):
                    continue
                if "kernel_module_name" in params:
                    migrated.add(name)
    return migrated

# Older plugins pass the pre-3.x config keys positionally instead:
#     list_processes(self.context,
#                    self.config['primary'],
#                    self.config['nt_symbols'],
#                    filter_func=...)
# 'primary' and 'nt_symbols' were the layer and symbol-table config entries
# before vol3 consolidated them into the single 'kernel' module requirement.
LEGACY_CONFIG_PAIR = re.compile(
    r"""(?P<head>\(\s*(?:self\.)?context\s*,\s*\n?\s*)
        self\.config\[['"]primary['"]\]\s*,\s*\n?\s*
        self\.config\[['"]nt_symbols['"]\]\s*,""",
    re.VERBOSE,
)


def resolve_namespace(text: str, module: str) -> str | None:
    """Work out which OS namespace a bare module reference belongs to.

    Several module names exist under more than one namespace with *different*
    versions — `windows.pslist.PsList` is 3.0.1 while `linux.pslist.PsList` is
    4.1.1. A file referring to `pslist.PsList` therefore cannot be resolved by
    name alone; the answer is in its import line:

        from volatility3.plugins.linux import pslist   -> linux
        from volatility3.plugins.windows import pslist -> windows

    Getting this wrong writes a plausible-looking but incorrect version and the
    plugin stays refused, which is exactly what happened to openssh_sessionkeys
    on the first pass.
    """
    pattern = (
        r"from\s+volatility3\.plugins\.(?P<ns>windows|linux|mac)(?:\.[\w.]+)?\s+import\s+"
        r"(?P<names>[^\n]+)"
    )
    for match in re.finditer(pattern, text):
        imported = [n.strip().split(" as ")[0] for n in match.group("names").split(",")]
        if module in imported:
            return match.group("ns")
    if re.search(rf"import\s+volatility3\.plugins\.linux\.{re.escape(module)}\b", text):
        return "linux"
    if re.search(rf"import\s+volatility3\.plugins\.windows\.{re.escape(module)}\b", text):
        return "windows"
    return None


def patch_source(text: str, versions: dict[str, tuple[int, int, int]]) -> tuple[str, list[str]]:
    notes: list[str] = []

    # 1. Bring PluginRequirement versions in line with what's installed.
    def bump(match: re.Match) -> str:
        plugin_ref = match.group("plugin")
        parts = plugin_ref.split(".")
        # References appear as "pslist.PsList" but also bare as "PsList" when
        # the class was imported directly, so fall back to matching on the
        # class name alone.
        key = ".".join(parts[-2:]) if len(parts) >= 2 else None
        actual = versions.get(key) if key else None
        if actual is None:
            cls_name = parts[-1]
            for known, version in versions.items():
                if known.split(".")[-1] == cls_name:
                    key, actual = known, version
                    break
        if actual is None:
            return match.group(0)
        # Prefer the namespace this file actually imports from, since the same
        # module name can exist under windows/ and linux/ with different
        # versions.
        if len(parts) >= 2:
            ns = resolve_namespace(text, parts[-2])
            if ns:
                ns_key = f"{ns}.{key}"
                if ns_key in versions:
                    key, actual = ns_key, versions[ns_key]
        declared = tuple(int(n) for n in re.findall(r"\d+", match.group("version")))
        # Volatility treats the major component as the compatibility barrier.
        if declared and declared[0] == actual[0]:
            return match.group(0)
        notes.append(f"{key}: {declared} -> {actual}")
        return match.group(0).replace(
            match.group("version"), f"({actual[0]}, {actual[1]}, {actual[2]})"
        )

    # Two spellings exist in the wild and both gate execution the same way:
    #   PluginRequirement(name=..., plugin=X, version=(...))
    #   VersionRequirement(name=..., component=X, version=(...))
    # (vol3 is deprecating the former in favour of the latter.)
    for requirement, arg in (("PluginRequirement", "plugin"), ("VersionRequirement", "component")):
        text = re.sub(
            requirement + r"\((?P<body>[^)]*?" + arg + r"\s*=\s*(?P<plugin>[\w.]+)[^)]*?"
            r"version\s*=\s*(?P<version>\([\d,\s]+\))[^)]*)\)",
            bump,
            text,
            flags=re.DOTALL,
        )

    # 2. Migrate layer_name + symbol_table -> kernel_module_name.
    text, n_kw = KWARG_PAIR.subn(
        lambda m: f'{m.group("indent")}kernel_module_name=self.config["kernel"],', text
    )
    if n_kw:
        notes.append(f"{n_kw} keyword call(s) -> kernel_module_name")

    migrated = migrated_methods()

    def rewrite_positional(m: re.Match) -> str:
        if m.group("method") not in migrated:
            return m.group(0)  # this API kept layer_name + symbol_table
        return f'{m.group("method")}{m.group("head")}self.config["kernel"]'

    text, n_pos = POSITIONAL_PAIR.subn(rewrite_positional, text)
    if n_pos:
        notes.append(f"{n_pos} positional call(s) -> kernel_module_name")

    text, n_legacy = LEGACY_CONFIG_PAIR.subn(
        lambda m: f'{m.group("head")}self.config["kernel"],', text
    )
    if n_legacy:
        notes.append(f"{n_legacy} legacy primary/nt_symbols call(s) -> kernel_module_name")

    return text, notes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="report only, don't write")
    parser.add_argument("dirs", nargs="*", type=Path, default=None)
    args = parser.parse_args()

    versions = installed_versions()
    if not versions:
        print("could not import any volatility3 core plugins — run this with the "
              "same interpreter that has volatility3 installed", file=sys.stderr)
        return 2
    print(f"installed core plugin versions: "
          f"{', '.join(f'{k}={v}' for k, v in sorted(versions.items()))}\n")

    dirs = args.dirs or DEFAULT_DIRS
    changed = 0
    for directory in dirs:
        for path in sorted(Path(directory).rglob("*.py")):
            original = path.read_text(encoding="utf-8")
            patched, notes = patch_source(original, versions)
            if patched == original:
                continue
            changed += 1
            rel = path.relative_to(REPO) if REPO in path.parents else path
            print(f"{'WOULD PATCH' if args.check else 'PATCHED'} {rel}")
            for note in notes:
                print(f"    - {note}")
            if not args.check:
                path.write_text(patched, encoding="utf-8")

    print(f"\n{changed} file(s) {'need patching' if args.check else 'patched'}")
    return 1 if (args.check and changed) else 0


if __name__ == "__main__":
    sys.exit(main())
