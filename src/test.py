# !/usr/bin/env -S python3 -m bpython -i

import time
from pyrenode3 import RPath
import System   # import sys
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import ICpuSupportingGdb


state_file= "statefile.dat"
e = Emulation()
m = Monitor()
# Tetsing for nrf52840.resc
mach = e.add_mach("nrf52840")
mach.load_repl("platforms/cpus/nrf52840.repl")
mach.load_elf("https://dl.antmicro.com/projects/renode/renode-nrf52840-zephyr_shell_module.elf-gf8d05cf-s_1310072-c00fbffd6b65c6238877c4fe52e8228c2a38bf1f")

pc_main = mach.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(pc_main)}")

def hook_addr_main(cpu, addr):
    print(f'Inside main hook. state_file_name : {state_file}')
    # mach.sysbus.cpu.Pause()
    m.execute(f"Save @{state_file}")
    print("machine paused at main, and state saved")
    

Action1 = getattr(System, 'Action`2')
hook_action_main = Action1[ICpuSupportingGdb, System.UInt64](hook_addr_main)

mach.sysbus.cpu.AddHook(pc_main,hook_action_main)
Analyzer(mach.sysbus.uart0).Show()

e.StartAll()
time.sleep(1)
mach.sysbus.cpu.RemoveHooksAt(pc_main)
m.execute("Clear")
print("cleared previous mach")
time.sleep(1)
print("Loading the saved file")

m.execute(f"Load @{state_file}")
nrf52840 = e.get_mach("nrf52840")
print(f"***Mach here : {nrf52840}")
Analyzer(nrf52840.sysbus.uart0).Show()

e.StartAll()


print("Done")
input()
