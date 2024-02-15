# !/usr/bin/env -S python3 -m bpython -i

from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import TranslationCPUHooksExtensions

e = Emulation()
m = Monitor()

# stm32l072 = e.add_mach("stm32l072")
# stm32l072.load_repl("platforms/cpus/stm32l072.repl")

# stm32l072.load_elf(
#     "https://dl.antmicro.com/projects/renode/stm32l07--zephyr-shell_module.elf-s_1195760-e9474da710aca88c89c7bddd362f7adb4b0c4b70"
# )

# Analyzer(stm32l072.sysbus.usart2).Show()

# e.StartAll()


# Tetsing for nrf52840.resc

nrf52840 = e.add_mach("nrf52840")
nrf52840.load_repl("platforms/cpus/nrf52840.repl")
nrf52840.load_elf("https://dl.antmicro.com/projects/renode/renode-nrf52840-zephyr_shell_module.elf-gf8d05cf-s_1310072-c00fbffd6b65c6238877c4fe52e8228c2a38bf1f")
# nrf52840.sysbus.cpu.SetHookAtBlockBegin(my_action)
TranslationCPUHooksExtensions.SetHookAtBlockBegin(nrf52840.sysbus.cpu.internal, nrf52840.internal, "print('hello world')")
Analyzer(nrf52840.sysbus.uart0).Show()
e.StartAll()
m.execute("sysbus.uart0 WriteChar 0x44")
m.execute("sysbus.uart0 WriteChar 0x46")


input()
