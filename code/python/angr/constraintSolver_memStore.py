import angr 
import claripy 

BINARY_DIR = '/home/xdoestech/Desktop/reverse_engineering/code/executables/fe01_dump_try2_SCY.exe'
proj = angr.Project(BINARY_DIR, load_options={'auto_load_libs': False})

# Create a symbolic bitvector for 'Serial', assuming it could be up to 12 characters of digits
serial_len = 12  # Maximum length of 'Serial'
serial_bvs = claripy.BVS('serial', serial_len*8)  # Create a symbolic bitvector for 'Serial'.

# Initialize the entry state
entry_state = proj.factory.entry_state(addr=0x00401183)  # Assuming start at function entry

# Set 'Name' to 'ted' concretely in memory
value_to_store = 0xc2d5be06
bytes_value = value_to_store.to_bytes(4, byteorder='little')
entry_state.memory.store(0x0019f8d4, bytes_value)
entry_state.memory.store(0x00403018, entry_state.solver.BVV(b'ted'))

# Assuming the 'Serial' input is at a different memory location, store it symbolically
serial_address = 0x0040304A  # Adjust this address as needed based on your binary analysis
entry_state.memory.store(serial_address, serial_bvs)

# Setup SimulationManager with the entry state
sim_mgr = proj.factory.simulation_manager(entry_state)

# Define the address to hook for comparison
comparison_addr = 0x004011cc

# Define a hook to check when eax equals ebx
def check_registers(state):
    print("Hook triggered.")
    print(f"eax={state.regs.eax}, ebx={state.regs.ebx}")
    if state.regs.eax == state.regs.ebx:
        print("EAX equals EBX condition met.")
        raise angr.exceptions.SimStateError("EAX equals EBX found!")
    else: 
        print(f"EAX does not equal EBX. eax={state.regs.eax}, ebx={state.regs.ebx}")

proj.hook(comparison_addr, check_registers)#, length=5)  # Hook at the comparison instruction

# Run the simulation manager
print("Starting simulation...")
sim_mgr.run()
print("Simulation completed.")

# Check if we have found a state where EAX equals EBX
if sim_mgr.deadended:
    for deadend in sim_mgr.deadended:
        if "EAX equals EBX found!" in deadend.history.descriptions:
            serial_value = deadend.solver.eval(serial_bvs, cast_to=bytes)
            print(f"Successful Serial: {serial_value.decode()}")
        
else:
    print("No solution found")

print(sim_mgr.deadended)



###############################################
#ERRORS: 
"""
WARNING  | 2024-05-06 15:40:58,780 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0xffff013e with 1 unconstrained bytes referenced from 0x40118a (offset 0x118a in fe01_dump_try2_SCY.exe (0x40118a))


"""