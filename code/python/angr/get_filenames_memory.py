import angr

def extract_filenames_and_addresses(binary_path):
    """Extracts filenames and their corresponding memory addresses from a binary.

    Args:
        binary_path (str): Path to the binary file.

    Returns:
        list: A list of tuples, where each tuple contains a filename string and
            its associated memory address as an integer.
    """

    project = angr.Project(binary_path, auto_load_libs=False)

    filenames_and_addresses = []

    # Analyze strings for filenames
    for addr, string in project.loader.main_object.memory.strings.items():  # Fixed: use .memory.strings
        if string.startswith("/") or string.startswith("\\"):  # Check for potential filename patterns
            filenames_and_addresses.append((string, addr))

    # Perform symbolic execution to potentially reveal more filenames
    state = project.factory.entry_state()
    simgr = project.factory.simulation_manager(state)

    while simgr.active:
        simgr.step()

        for state in simgr.active:
            for addr, string in state.solver.eval_upto(project.loader.main_object.memory, 255, cast_to=bytes).items():
                if string.startswith("/") or string.startswith("\\"):
                    filenames_and_addresses.append((string, addr))

    return filenames_and_addresses

extract_filenames_and_addresses("/home/xdoestech/Desktop/reverse_engineering/myFirst_crackme/first_crack")