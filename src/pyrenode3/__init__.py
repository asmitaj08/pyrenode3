import importlib
import logging
import os
from pyrenode3.loader import RenodeLoader

renode_path = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/renode"
if "PYRENODE_SKIP_LOAD" not in os.environ:
    # if (pkg := os.environ.get("PYRENODE_ARCH_PKG")) is not None:
    #     RenodeLoader.from_arch(pkg)

    # if (pkg := os.environ.get("PYRENODE_BUILD_DIR")) is not None:
    RenodeLoader.from_mono_build(renode_path)

    if not RenodeLoader().is_initialized:
        msg = (
            f"Renode not found. Please do one of following actions:\n"
            f"   - install Renode from a package\n"
            f"   - set {env.PYRENODE_PKG} to the location of the Renode package\n"
            f"   - set {env.PYRENODE_BUILD_DIR} to the location of the Renode build directory\n"
            f"   - set {env.PYRENODE_BIN} to the location of the Renode portable binary\n"
        )
        raise ImportError(msg)

    # this prevents circular imports
    importlib.import_module("pyrenode3.wrappers")

    from pyrenode3.conversion import interface_to_class
    from pyrenode3.rpath import RPath

__all__ = [
    "RPath",
    "interface_to_class",
    "wrappers",
]
