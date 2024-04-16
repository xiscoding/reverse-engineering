import angr 
import claripy 

BINARY_DIR = '/home/xdoestech/Desktop/reverse_engineering/code/executables/yeungrebecca_170091_32959806_crackme'

proj = angr.Project(BINARY_DIR, main_opts = {"base_addr": 0})
#proj = angr.Project(BINARY_DIR)

#create bitvector of 32 chars
password_chars = [claripy.BVS("flag_%d" % i, 8) for i in range(32)]
#concat symbolic variables into one large symbolic variable
password_ast = claripy.Concat(*password_chars)

#define starting initial state 
#state = proj.factory.entry_state(stdin=angr.SimFileStream(name='stdin', content=password_ast, has_end=False))
state = proj.factory.entry_state(stdin=angr.SimFileStream(name='stdin', content=password_ast, has_end=False),
                                 add_options={
                                     angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                     angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY
                                 })
#define simulation manager with initial state
sim_mgr = proj.factory.simulation_manager(state)

#preform analyis find success addr avoid fail_addr
#in main find the 
success_addr = 0x1320
fail_addr = 0x1339
sim_mgr.explore(find=success_addr, avoid=[fail_addr])

if len(sim_mgr.found) > 0:
    print("Solution found")
    found = sim_mgr.found[0]
    found_password = found.solver.eval(password_ast, cast_to=bytes)
    print("%s" % found_password)
else:
    print("No solution found")