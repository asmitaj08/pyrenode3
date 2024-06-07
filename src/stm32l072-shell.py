# !/usr/bin/env -S python3 -m bpython -i

import time
from pyrenode3 import RPath
import System   # import sys
from pyrenode3.wrappers import Analyzer, Emulation, Monitor
from Antmicro.Renode.Peripherals.CPU import TranslationCPUHooksExtensions
from Antmicro.Renode.Peripherals.CPU import TranslationCPU # src/Infrastructure/src/Emulator/Peripherals/Peripherals/CPU/TranslationCPU.cs
from Antmicro.Renode.Peripherals.CPU import RegisterValue # src/Infrastructure/src/Emulator/Main/Peripherals/CPU/RegisterValue.cs
from Antmicro.Renode.Peripherals.CPU import ICPUWithRegisters #src/Infrastructure/src/Emulator/Main/Peripherals/CPU/ICPUWithRegisters.cs
from Antmicro.Renode.Peripherals.CPU import ICpuSupportingGdb
from Antmicro.Renode.Hooks import CpuHooksExtensions
from Antmicro.Renode.PlatformDescription.UserInterface import PlatformDescriptionMachineExtensions
from Antmicro.Renode.Peripherals.I2C import BME280 # src/Infrastructure/src/Emulator/Peripherals/Peripherals/I2C/BME280.cs

state_file= "/home/asmita/fuzzing_bare-metal/SEFF_project_dirs/SEFF-project/LibAFL/fuzzers/libafl_renode/statefile.dat"
mach_name = "stm"
# src/Infrastructure/src/Emulator/Extensions/Hooks/BlockPythonEngine.cs
e = Emulation()
m = Monitor()
# Tetsing for nrf52840.resc

mach = e.add_mach(mach_name)
# mach.load_repl("platforms/cpus/nrf52840.repl")
# mach.load_elf("https://dl.antmicro.com/projects/renode/renode-nrf52840-zephyr_shell_module.elf-gf8d05cf-s_1310072-c00fbffd6b65c6238877c4fe52e8228c2a38bf1f")

# mach.load_repl("platforms/cpus/stm32l072.repl")

load_str = """using "platforms/cpus/stm32l072.repl" bme280: I2C.BME280@ i2c1 0x76"""
PlatformDescriptionMachineExtensions.LoadPlatformDescriptionFromString(mach.internal,load_str)
mach.load_elf("https://dl.antmicro.com/projects/renode/b_l072z_lrwan1--zephyr-bme280_test.elf-s_649120-15b7607a51b50245f4500257c871cd754cfeca5a")

print("loaded")
# nrf52840.load_elf("/media/asmita/224870c0-ff7f-4009-9ea0-79854d3c355a/nrfSDK/DeviceDownload/nRF5_SDK_17.1.0_ddde560/examples/peripheral/uart/pca10056/blank/armgcc/_build/nrf52840_xxaa.out")


# COV_MAP_SIZE = 8*1024
# COVMAP = [0] * COV_MAP_SIZE
# PREV_LOC = 0

sp_main=0
lr_main=0
pc_main = 0

sp_target=0
lr_target=0
pc_target=0

target_func_name = "i2c_read_reg"
target_func_calling_pc = 0x0800353a # address from where target_func is called
# target_func_lr = 0x143e # return address of target fun , this doesn't matter actually
# reach_goal_pc = 0x1456 # address after which code resumes to teh target func with ok
# exit_addr = 0x145a
reach_target_flag = 0
reach_goal_flag = 0
exit_flag = 0
pc_main = mach.sysbus.GetSymbolAddress("main")
print(f"Main func addr : {hex(pc_main)}")
print(f"Target func addr : {hex(mach.sysbus.GetSymbolAddress('bme280_reg_read_i2c'))}")

input_data = 30
# pc_target = nrf52840.sysbus.GetSymbolAddress(target_func_name)
# print(f"Target function is {target_func_name} at {pc_target}")

# def hook_block(pc, size):
#     # print(f"Block Hook **** : {hex(pc)}")
#     with open('block_hook_log.txt','a') as f:
#         f.write(f'Block Hook **** : {hex(pc)}\n')
    # pass
    # global COVMAP, PREV_LOC, COV_MAP_SIZE
    # hash_val = (pc ^ PREV_LOC) & (COV_MAP_SIZE - 1)
    # COVMAP[hash_val] += 1
    # PREV_LOC = pc >> 1

def hook_addr_main(cpu, addr):
    # print(f"CPU Addr Hook **** : {hex(addr)}")
    global lr_main, sp_main
    sp_main = mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue  
    # pc_val = nrf52840.sysbus.cpu.GetRegisterUnsafe(15).RawValue
    lr_main = mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue
    print(f"Main : SP: {hex(sp_main)}, PC: {hex(addr)}, LR: {hex(lr_main)}, sp_val:{mach.sysbus.ReadDoubleWord(sp_main-12)}")
    mach.sysbus.cpu.Pause()
    # print(f"reg values : {nrf52840.sysbus.cpu.GetRegisterValues()}")
    print("machine paused at main")
    

def hook_addr_goal(cpu,addr):
    global reach_goal_flag
    reach_goal_flag = 1
    # print(f"Reached {hex(addr)}, flag : {reach_goal_flag}")
    # nrf52840.sysbus.cpu.Pause()
    # nrf52840.sysbus.cpu.PC = RegisterValue.Create(pc_init, 32)
    # or
    # nrf52840.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(target_func_calling_pc, 32))
    # nrf52840.sysbus.cpu.SetRegisterUnsafe(14, RegisterValue.Create(target_func_lr, 32))
    # print("reg set")
    # print(f"goal_addr : PC: {hex(nrf52840.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}, LR :{hex(nrf52840.sysbus.cpu.GetRegisterUnsafe(14).RawValue)}")
    # nrf52840.sysbus.cpu.Resume()
    # m.execute(f"sysbus.uart0 WriteChar {input_data}")

def hook_addr_target(cpu,addr):
    global reach_target_flag,m, state_file, nrf52840, sp_target, lr_target
    reach_target_flag = 1
    sp_target = mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue
    # lr_target = nrf52840.sysbus.cpu.GetRegisterUnsafe(14).RawValue  
    # print(f"machine paused at target. {hex(sp_target)}, {hex(lr_target)}")
    # m.execute(f"Save @{state_file}")
    mach.sysbus.cpu.Pause()
    # print(f"reg values : {nrf52840.sysbus.cpu.GetRegisterValues()}")
    # print(f"machine paused at target. {hex(sp_target)}, {hex(lr_target)}")
   
    # m.execute(f"Save @{state_file}")
    # print("********reached target, saving state")
    # # m.execute(f"Save @stateFile.dat")
    # m.execute("Clear")
    

def hook_addr_exit(cpu,addr):
    global exit_flag, nrf52840, input_data
    exit_flag = 1
    return 0
    # print(f"machine paused at exit. Pc : {nrf52840.sysbus.cpu.PC}")
    # nrf52840.sysbus.cpu.Pause()
    # input_data+=1
    # nrf52840.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(target_func_calling_pc, 32))
    # nrf52840.sysbus.cpu.SetRegisterUnsafe(14, RegisterValue.Create(target_func_lr, 32))
    # nrf52840.sysbus.cpu.Resume()
   
# Action = getattr(System, 'Action`2')
# hook_action1 = Action[System.UInt64,System.UInt32](hook_block)
# nrf52840.sysbus.cpu.SetHookAtBlockBegin(hook_action1)
# TranslationCPUHooksExtensions.SetHookAtBlockBegin(mach.sysbus.cpu.internal, mach.internal, " ")

# CpuHooksExtensions.AddHook(nrf52840.sysbus.cpu.internal, nrf52840.internal,main_func_addr, "")
Action1 = getattr(System, 'Action`2')
hook_action_main = Action1[ICpuSupportingGdb, System.UInt64](hook_addr_main)

Action2 = getattr(System, 'Action`2')
hook_action_goal = Action2[ICpuSupportingGdb, System.UInt64](hook_addr_goal)

Action3 = getattr(System, 'Action`2')
hook_action_target = Action3[ICpuSupportingGdb, System.UInt64](hook_addr_target)

Action4 = getattr(System, 'Action`2')
hook_action_exit = Action4[ICpuSupportingGdb, System.UInt64](hook_addr_exit)

mach.sysbus.cpu.AddHook(pc_main,hook_action_main)
# mach.sysbus.cpu.AddHook(reach_goal_pc,hook_action_goal)
# mach.sysbus.cpu.AddHook(target_func_calling_pc,hook_action_target)
BME280_sen=BME280()
Analyzer(mach.sysbus.usart2).Show()
# BME280_sen.Temperature = 45.00
BME280_sen.Humidity = 88.00
time.sleep(1)
# BME280_sen.Pressure = 1000.00
# Analyzer(mach.sysbus.i2c1).Show()
e.StartAll()
# while reach_target_flag == 0 :
#     print("flag 0")
#     print(f"##### PC: {hex(nrf52840.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}, {hex(nrf52840.sysbus.cpu.GetRegisterUnsafe(14).RawValue)}")

#     pass
time.sleep(1)
print(f'Flag : {reach_target_flag}')
# reach_target_flag = 0
# print(f'Updated Flag : {reach_target_flag}')
# mach.sysbus.cpu.Pause()
# mach.sysbus.cpu.RemoveHooksAt(target_func_calling_pc)
mach.sysbus.cpu.RemoveHooksAt(pc_main)
print(f'{BME280_sen.Temperature},{BME280_sen.Humidity},{BME280_sen.Pressure}')
print('Removed target func Hook')
# nrf52840.sysbus.cpu.Resume()
# nrf52840.sysbus.cpu.AddHook(reach_goal_pc,hook_action_goal)
# nrf52840.sysbus.cpu.AddHook(exit_addr,hook_action_exit)
# m.Save(state_file)
# m.execute(f"Save @{state_file}")
# m.execute("Clear")

# print("********reached target, saving state")
# m.execute(f"Save @{state_file}")
# print("****saved , clearing")
# m.execute("Clear")
# print(f"saved state file at : {state_file}")
# print("removed hook_addr at main")
# print("Sending")
# m.execute("sysbus.uart0 WriteChar 0x44")
def harness_fn():
    global input_data, reach_goal_flag,exit_flag,e,m, mach, sp_target, target_func_calling_pc,pc_main,sp_main,BME280_sen

    mach.sysbus.cpu.Pause()
    input_data+=1
    # print(f"Inside harness function {hex(sp_target)},{(mach.sysbus.cpu.PC)}")
    mach.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(pc_main, 32))
    mach.sysbus.cpu.SetRegisterUnsafe(13, RegisterValue.Create(sp_main, 32))
    # nrf52840.sysbus.cpu.SetRegisterUnsafe(14, RegisterValue.Create(lr_target, 32))
    # nrf52840.sysbus.cpu.SetRegisterUnsafe(13, RegisterValue.Create(sp_target, 32))
    # nrf52840.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(pc_main, 32))
    # # nrf52840.sysbus.cpu.SetRegisterUnsafe(14, RegisterValue.Create(lr_main, 32))
    # # nrf52840.sysbus.cpu.SetRegisterUnsafe(13, RegisterValue.Create(sp_main, 32))
    # print(f"before resume. {hex(nrf52840.sysbus.cpu.GetRegisterUnsafe(13).RawValue)}, {hex(nrf52840.sysbus.cpu.GetRegisterUnsafe(14).RawValue)}, {hex(nrf52840.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
    # m.execute(f"i2c1.bme280 Temperature {input_data}")
    # mach.sysbus.i2c1.bme280.Write([0x18, 0x23, 0x45])
    # BME280_sen.Temperature = 45.00
    BME280_sen.Humidity = 100.00
    time.sleep(1)
    # BME280_sen.Pressure = 1000.00
    mach.sysbus.cpu.Resume()
    # BME280_sen.Temperature = 45.00
    # BME280_sen.Humidity = 100.00
    # BME280_sen.Pressure = 1000.00
    # mach.sysbus.i2c1.bme280.Write([0x18, 0x23, 0x45])
    # print(f'addr_before : {mach.sysbus.cpu.PC} , reading sensor : { mach.sysbus.i2c1.bme280.Read(3)}, addr_after : {(mach.sysbus.cpu.PC)}')
    # m.execute(f"sysbus.uart0 WriteChar {input_data}")
    # m.execute(f"i2c1.bme280 Temperature {25}")
    # time.sleep(1)
    print(f'{BME280_sen.Temperature},{BME280_sen.Humidity},{BME280_sen.Pressure}')

    # print(f"done one run. {hex(mach.sysbus.cpu.GetRegisterUnsafe(13).RawValue)}, {hex(mach.sysbus.cpu.GetRegisterUnsafe(14).RawValue)}, {hex(mach.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}")
# print(f"Loading from : {state_file}")
# print(m)
# m.execute(f"Load @{state_file}")
# # m.execute(f"Load @{state_file}")
# print("******Loaded state")
# nrf52840 = e.get_mach("nrf52840")
# print(nrf52840)
    # nrf52840.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(target_func_calling_pc, 32))
    # nrf52840.sysbus.cpu.SetRegisterUnsafe(14, RegisterValue.Create(target_func_lr, 32))
    # nrf52840.sysbus.cpu.Resume()
    # m.execute(f"sysbus.uart0 WriteChar {input_data}")
    # while reach_goal_flag==0:
    #     pass

    # print(f"exit_f : {exit_flag},goal_flag : {reach_goal_flag}")
    # if exit_flag == 1 :
    #     print("exit flag **")
    #     m.execute("Clear")
    #     exit()
    # if reach_goal_flag == 1:
    #     # nrf52840.sysbus.cpu.Pause()
    #     reach_goal_flag=0
    #     m.execute("Clear")
    #     harness_fn()
    # else :
    #     print("break**")
    #     exit()
    

while True :
    harness_fn()
    # print(f"reach_goal_flag : {reach_goal_flag}")
    # if exit_flag==1 :

    # while exit_flag==0:
    #     pass
    # nrf52840.sysbus.cpu.PC = RegisterValue.Create(target_func_calling_pc, 32)
    
    # print(f"updated_addr : PC: {hex(nrf52840.sysbus.cpu.GetRegisterUnsafe(15).RawValue)}, {hex(nrf52840.sysbus.cpu.GetRegisterUnsafe(14).RawValue)}")

    # # print(f"Reached goal : {reach_goal_flag}")
    # if reach_goal_flag == 1:
    #     nrf52840.sysbus.cpu.Pause()
    #     reach_goal_flag=0
    #     harness_fn()
    # else :
    #     print("break**")
    #     break
    
# # pc_val = m.execute("sysbus.cpu PC")
# # m.execute("Clear")

# # print(pc_val)
# print(nrf52840.sysbus.cpu.PC)

# # m.execute("pause")
# nrf52840.sysbus.cpu.Pause()
# # nrf52840.sysbus.cpu.PC = RegisterValue.Create(pc_init, 32)
# # or 
# nrf52840.sysbus.cpu.SetRegisterUnsafe(15, RegisterValue.Create(pc_init, 32))
# nrf52840.sysbus.cpu.SP = RegisterValue.Create(sp_init, 32)
# # nrf52840.sysbus.cpu.PC = pc_init
# print("****#####")
# print(nrf52840.sysbus.cpu.PC)
# # pc_val = m.execute("sysbus.cpu PC")
# # # m.execute("Clear")
# nrf52840.sysbus.cpu.Resume()
# # print(pc_val)

# m.execute("sysbus.uart0 WriteChar 0x42")
# print(nrf52840.sysbus.cpu.PC)
# # sp=TranslationCPU.GetRegisterUnsafe(another_register_id).RawValue

print("Done")
input()
