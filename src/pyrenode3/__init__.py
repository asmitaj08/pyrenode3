import importlib
import logging
import os
import sys

from pyrenode3.loader import RenodeLoader

renode_path = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/renode"
if "PYRENODE_SKIP_LOAD" not in os.environ:
    # if (pkg := os.environ.get("PYRENODE_ARCH_PKG")) is not None:
    #     RenodeLoader.from_arch(pkg)

    # if (pkg := os.environ.get("PYRENODE_BUILD_DIR")) is not None:
    RenodeLoader.from_mono_build(renode_path)

    if not RenodeLoader().is_initialized:
        logging.critical("Set PYRENODE_ARCH_PKG to the location of renode arch package.")
        sys.exit(1)

    # this prevents circular imports
    importlib.import_module("pyrenode3.wrappers")

    from pyrenode3.conversion import interface_to_class
    from pyrenode3.rpath import RPath

__all__ = [
    "RPath",
    "interface_to_class",
    "wrappers",
]
