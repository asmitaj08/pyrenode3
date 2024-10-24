# !/usr/bin/env -S python3 -m bpython -i
# from os import system
from pyrenode3 import RPath
import System # import sys
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import TranslationCPUHooksExtensions
from Antmicro.Renode.Peripherals.CPU import TranslationCPU # src/Infrastructure/src/Emulator/Peripherals/Peripherals/CPU/TranslationCPU.cs
from Antmicro.Renode.Peripherals.CPU import RegisterValue # src/Infrastructure/src/Emulator/Main/Peripherals/CPU/RegisterValue.cs
from Antmicro.Renode.Peripherals.CPU import ICPUWithRegisters #src/Infrastructure/src/Emulator/Main/Peripherals/CPU/ICPUWithRegisters.cs
from Antmicro.Renode.Peripherals.CPU import ICpuSupportingGdb
from Antmicro.Renode.Hooks import CpuHooksExtensions

# src/Infrastructure/src/Emulator/Extensions/Hooks/BlockPythonEngine.cs
e = Emulation()
m = Monitor()

# state_file = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/pyrenode3/src/statefile.dat"
state_file= "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/statefile.dat"

# log_file = "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/pyrenode3/src/log.txt"

# stm32l072 = e.add_mach("stm32l072")
# stm32l072.load_repl("platforms/cpus/stm32l072.repl")

# stm32l072.load_elf(
#     "https://dl.antmicro.com/projects/renode/stm32l07--zephyr-shell_module.elf-s_1195760-e9474da710aca88c89c7bddd362f7adb4b0c4b70"
# )

# Analyzer(stm32l072.sysbus.usart2).Show()

# e.StartAll()


# Tetsing for nrf52840.resc

# m.execute(f"logFile @{log_file}")
# def block_hook(cpu, address):
#     print(f"Block Hook **** : {hex(address)}")

# Action_block = getattr(System, 'Action`3')
# hook_action1 = Action_block[System.UInt64,System.UInt32](block_hook)

nrf52840 = e.add_mach("nrf52840")
nrf52840.load_repl("platforms/cpus/nrf52840.repl")
# nrf52840.load_elf("https://dl.antmicro.com/projects/renode/renode-nrf52840-zephyr_shell_module.elf-gf8d05cf-s_1310072-c00fbffd6b65c6238877c4fe52e8228c2a38bf1f")
nrf52840.load_elf("/media/asmita/224870c0-ff7f-4009-9ea0-79854d3c355a/nrfSDK/DeviceDownload/nRF5_SDK_17.1.0_ddde560/examples/peripheral/uart/pca10056/blank/armgcc/_build/nrf52840_xxaa.out")

# python_script = """print('hello')"""

# nrf52840.sysbus.cpu.SetHookAtBlockBegin(hook_action1)
# TranslationCPUHooksExtensions.SetHookAtBlockBegin(nrf52840.sysbus.cpu.internal, nrf52840.internal, "")

# TranslationCPUHooksExtensions.SetHookAtBlockBegin(nrf52840.sysbus.cpu.internal, nrf52840.internal, " ")

# The reason the second approach doesn't work in Python is because the LogFunctionNames method is an instance method, not a static method.

# cpu_instance = TranslationCPU()
# cpu_instance.LogFunctionNames(True)
# The error TypeError: cannot instantiate abstract class occurs because you're trying to instantiate an abstract class (TranslationCPU), which is not allowed in Python.
# Create a subclass of TranslationCPU
# class MyTranslationCPU1(TranslationCPU):
#     @property
#     def GDBArchitecture(self):
#         # Implement the GDBArchitecture property
#         return "x86"  # Example implementation, replace with your logic

#     @property
#     def GDBFeatures(self):
#         # Implement the GDBFeatures property
#         return []  # Example implementation, replace with your logic

#     def DecodeInterrupt(self, number):
#         # Implement the DecodeInterrupt method
#         pass  # Example implementation, replace with your logic

#     def SetRegisterUnsafe(self, register, value):
#         # Implement the SetRegisterUnsafe method
#         pass  # Example implementation, replace with your logic

#     def GetRegisterUnsafe(self, register):
#         # Implement the GetRegisterUnsafe method
#         pass  # Example implementation, replace with your logic

#     def GetRegisters(self):
#         # Implement the GetRegisters method
#         return []  # Example implementation, replace with your logic


# # Instantiate the subclass
# cpu_instance = MyTranslationCPU1()
# cpu_instance.LogFunctionNames(True)
#  The above gives error because of abstract class

# m.execute("sysbus.cpu LogFunctionNames true")
TranslationCPUHooksExtensions.SetHookAtBlockBegin(nrf52840.sysbus.cpu.internal, nrf52840.internal, " ")

Analyzer(nrf52840.sysbus.uart0).Show()
e.StartAll()
# m.execute("sysbus.uart0 WriteChar 0x44")
# pc_val_i = m.execute("sysbus.cpu PC")
# # m.execute("Clear")

# print(pc_val_i)

# m.execute("sysbus.cpu LogFunctionNames true")
m.execute(f"Save @{state_file}")
# sp_init = nrf52840.sysbus.cpu.SP
# pc_init = nrf52840.sysbus.cpu.PC
sp_init = nrf52840.sysbus.cpu.GetRegisterUnsafe(13).RawValue
pc_init = nrf52840.sysbus.cpu.GetRegisterUnsafe(15).RawValue
lr_init = nrf52840.sysbus.cpu.GetRegisterUnsafe(14).RawValue
print(hex(sp_init))
print(hex(pc_init))
print(hex(lr_init))

main_func_addr = nrf52840.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(main_func_addr)}")

m.execute("Clear")

def hook_main(cpu, address):
    print(f"CPU Hook **** : {hex(address)}")

Action = getattr(System, 'Action`2')
hook_action = Action[ICpuSupportingGdb, System.UInt64](hook_main)

print("Saved, and loading again")
# m.execute(f"logFile @{log_file}")
m.execute(f"Load @{state_file}")
nrf52840 = e.get_mach("nrf52840")
print(f"***MAch here : {nrf52840}")
# python_script1 = """print(f'hello from cpu hook at {0x62c}')""" (can't do this, gives whne f'{})

nrf52840.sysbus.cpu.AddHook(main_func_addr,hook_action)
# CpuHooksExtensions.AddHook(nrf52840.sysbus.cpu.internal, nrf52840.internal,main_func_addr, "")

Analyzer(nrf52840.sysbus.uart0)
# m.execute(f"logFile @{log_file}")
e.StartAll()
# pc_val_2 = m.execute("sysbus.cpu PC")
# # m.execute("Clear")

# print(pc_val_2)
print(nrf52840.sysbus.cpu.PC)
print("****")
Analyzer(nrf52840.sysbus.uart0).Show()
m.execute("sysbus.uart0 WriteChar 0x44")
# pc_val = m.execute("sysbus.cpu PC")
# m.execute("Clear")

# print(pc_val)
print(nrf52840.sysbus.cpu.PC)

# m.execute("pause")
nrf52840.sysbus.cpu.Pause()
# nrf52840.sysbus.cpu.PC = RegisterValue.Create(pc_init, 32)
# or 
nrf52840.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(pc_init, 13))
nrf52840.sysbus.cpu.SP = RegisterValue.Create(sp_init, 32)
# nrf52840.sysbus.cpu.PC = pc_init
print("****#####")
print(nrf52840.sysbus.cpu.PC)
# pc_val = m.execute("sysbus.cpu PC")
# # m.execute("Clear")
nrf52840.sysbus.cpu.Resume()
# print(pc_val)

m.execute("sysbus.uart0 WriteChar 0x42")
print(nrf52840.sysbus.cpu.PC)
# sp=TranslationCPU.GetRegisterUnsafe(another_register_id).RawValue

print("Done")
input()


# src/Infrastructure/src/Emulator/Peripherals/Peripherals/I2C/NRF52840_I2C.cs 
# public class NRF52840_I2C : SimpleContainer<II2CPeripheral>, IProvidesRegisterCollection<DoubleWordRegisterCollection>, IDoubleWordPeripheral, IKnownSize

#print added in these :
# src/Infrastructure/src/Emulator/Peripherals/Peripherals/I2C/STM32F7_I2C.cs