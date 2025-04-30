"""
File Name: Static-String-Deobfuscation-Function-Detection/v.1.0/deobfuscation_analysis_helpers.py
Purpose: Helper functions for the deobfuscation candidate finder.
Date Last Modified: 15 April 2025
Author: Kelsie A. Edie (kelsie_edie@brown.edu)
"""

import statistics
import math

# Global constants for section names and instruction mnemonics.
GLOBAL_SECTIONS = [
    "data", "rdata", "rodata", "bss",
    "sdata", "sbss",
    "edata", "idata", "text"
]

XOR_MNEMONIC = "XOR"
MOV_MNEMONICS = ["MOV", "MOVD", "MOVZX", "VMOV", "MOVAPS", "MOVUPS"]
JUMP_MNEMONICS = [
    "JMP", "JE", "JNE", "JG", "JGE", "JL", "JLE",
    "JC", "JNC", "JZ", "JNZ", "JA", "JAE", "JB", "JBE",
    "JO", "JNO", "JS", "JNS"
]


def compute_entropy(s):
    """
    Compute the Shannon entropy of a given string.

    Parameters:
        s (str): The input string.

    Returns:
        float: The Shannon entropy (in bits) of the string.
    """
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def build_call_graph(program, func_info):
    """
    Build a call graph for the given program where each caller is associated with its name and address,
    and each callee is represented similarly.

    Parameters:
        program: The Ghidra Program object to analyze.
        func_info: A dictionary mapping function addresses (as strings) to their info dictionaries.

    Returns:
        dict: A dictionary representing the call graph. Keys are caller addresses, and values are dictionaries
              with 'caller' (info dict) and 'callees' (list of callee info dicts).
    """
    call_graph = {}
    try:
        listing = program.getListing()
        function_manager = program.getFunctionManager()
        refManager = program.getReferenceManager()
        from ghidra.util.task import ConsoleTaskMonitor
        monitor = ConsoleTaskMonitor()
        functions = list(function_manager.getFunctions(True))
        for function in functions:
            try:
                caller_addr = function.getEntryPoint().toString()
                caller_info = func_info.get(
                    caller_addr, {"name": function.getName(), "address": caller_addr}
                )
                call_graph[caller_addr] = {"caller": caller_info, "callees": []}
                for instr in listing.getInstructions(function.getBody(), True):
                    try:
                        mnemonic = instr.getMnemonicString().upper()
                        if "CALL" in mnemonic:
                            for ref in refManager.getReferencesFrom(instr.getAddress()):
                                try:
                                    if ref.getReferenceType().isCall():
                                        target_addr = ref.getToAddress().toString()
                                        callee_info = func_info.get(
                                            target_addr, {"name": target_addr, "address": target_addr}
                                        )
                                        call_graph[caller_addr]["callees"].append(callee_info)
                                except Exception as inner3_e:
                                    print(f"Error processing call ref at {instr.getAddress()}: {inner3_e}")
                    except Exception as inner2_e:
                        print(f"Error processing instruction in call graph: {inner2_e}")
            except Exception as outer_e:
                print(f"Error processing function {function.getName()}: {outer_e}")
        return call_graph
    except Exception as e:
        print(f"Error in build_call_graph: {e}")
        return {}


def is_global_data_address(address, memory):
    """
    Check if the given address belongs to a global data section.

    Parameters:
        address: The address to check.
        memory: The Ghidra Memory object.

    Returns:
        bool: True if the address is in a global data section; otherwise, False.
    """
    try:
        block = memory.getBlock(address)
        if block is None:
            return False
        block_name = str(block.getName()).lower().lstrip('.')
        for section in GLOBAL_SECTIONS:
            if section.lower().lstrip('.') in block_name:
                return True
        return False
    except Exception as e:
        print(f"Error in is_global_data_address: {e}")
        return False


def is_loop_detected(function, program):
    """
    Determine if the function contains a loop by reconstructing its control flow graph (CFG).

    Parameters:
        function: The function object from the program.
        program: The Ghidra Program object.

    Returns:
        bool: True if any cycle (loop) is found in the CFG; otherwise, False.
    """
    try:
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra.program.model.block import BasicBlockModel
        monitor = ConsoleTaskMonitor()
        bbm = BasicBlockModel(program)
        blocks = []
        block_iter = bbm.getCodeBlocksContaining(function.getBody(), monitor)
        while block_iter.hasNext():
            try:
                blocks.append(block_iter.next())
            except Exception as inner_e:
                print(f"Error iterating blocks: {inner_e}")

        # Build a control flow graph (CFG) mapping each block to its successors.
        cfg = {}
        for block in blocks:
            successors = []
            try:
                dest_iter = block.getDestinations(monitor)
                while dest_iter.hasNext():
                    try:
                        dest_ref = dest_iter.next()
                        dest_block = dest_ref.getDestinationBlock()
                        if dest_block is not None:
                            successors.append(dest_block)
                    except Exception as inner2_e:
                        print(f"Error processing destination in block {block}: {inner2_e}")
                cfg[block] = successors
            except Exception as e_inner:
                print(f"Error building CFG for block {block}: {e_inner}")
        visited = set()
        rec_stack = set()

        def dfs(block):
            try:
                visited.add(block)
                rec_stack.add(block)
                for succ in cfg.get(block, []):
                    if succ not in visited:
                        if dfs(succ):
                            return True
                    elif succ in rec_stack:
                        return True
                rec_stack.remove(block)
                return False
            except Exception as dfs_e:
                print(f"Error in DFS: {dfs_e}")
                return False

        for block in blocks:
            if block not in visited:
                if dfs(block):
                    return True
        return False
    except Exception as e:
        print(f"Error in is_loop_detected: {e}")
        return False


def count_global_references(function, listing, refManager, memory):
    """
    Count the read and write references in a function's instructions that point to global data.

    Parameters:
        function: The function object.
        listing: The program's listing obtained from getListing().
        refManager: The Reference Manager from the program.
        memory: The Ghidra Memory object.

    Returns:
        tuple: A tuple (reads, writes), where reads is the count of global data reads
               and writes is the count of writes.
    """
    reads = 0
    writes = 0
    try:
        for instr in listing.getInstructions(function.getBody(), True):
            try:
                for ref in refManager.getReferencesFrom(instr.getAddress()):
                    if is_global_data_address(ref.getToAddress(), memory):
                        if ref.getReferenceType().isRead():
                            reads += 1
                        if ref.getReferenceType().isWrite():
                            writes += 1
            except Exception as inner_e:
                print(f"Error processing instruction at {instr.getAddress()}: {inner_e}")
        return reads, writes
    except Exception as e:
        print(f"Error in count_global_references: {e}")
        return 0, 0


def count_non_zeroing_xor(instructions):
    """
    Count XOR instructions in the provided instruction list that do not simply zero a register.

    Parameters:
        instructions (list): A list of instruction objects.

    Returns:
        int: The count of non-zeroing XOR instructions.
    """
    count = 0
    try:
        for instr in instructions:
            try:
                if instr.getMnemonicString().upper() == XOR_MNEMONIC:
                    # grab the raw operand objects (could be Register, Scalar, Address, etc.)
                    op0 = instr.getOpObjects(0)
                    op1 = instr.getOpObjects(1)
                    # if they’re not identical (e.g. EAX vs EAX), count it
                    if op0 != op1:
                        count += 1
            except Exception as inner:
                print(f"Error processing XOR at {instr.getAddress()}: {inner}")
        return count

    except Exception as e:
        print(f"Error in count_non_zeroing_xor: {e}")
        return 0


def count_call_instructions(function, listing):
    """
    Count the total number of call instructions within a function.

    Parameters:
        function: The function object.
        listing: The program listing.

    Returns:
        int: The count of call instructions.
    """
    count = 0
    try:
        for instr in listing.getInstructions(function.getBody(), True):
            try:
                if "CALL" in instr.getMnemonicString().upper():
                    count += 1
            except Exception as inner_e:
                print(f"Error processing call instruction at {instr.getAddress()}: {inner_e}")
        return count
    except Exception as e:
        print(f"Error in count_call_instructions: {e}")
        return 0


def count_xref(function, refManager):
    """
    Count the number of cross-references (incoming calls) to the function's entry point.

    Parameters:
        function: The function object.
        refManager: The Reference Manager.

    Returns:
        int: The number of incoming cross-references.
    """
    try:
        entry = function.getEntryPoint()
        refs = list(refManager.getReferencesTo(entry))
        return len(refs)
    except Exception as e:
        print(f"Error in count_xref: {e}")
        return 0


def get_loop_blocks(function, program):
    """
    Reconstruct the control flow graph (CFG) of a function and return all basic blocks that participate in a loop.

    Parameters:
        function: The function object.
        program: The Ghidra Program object.

    Returns:
        set: A set of basic blocks that are part of a loop.
    """
    try:
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra.program.model.block import BasicBlockModel
        monitor = ConsoleTaskMonitor()
        bbm = BasicBlockModel(program)
        blocks = []
        block_iter = bbm.getCodeBlocksContaining(function.getBody(), monitor)
        while block_iter.hasNext():
            try:
                blocks.append(block_iter.next())
            except Exception as e_inner:
                print(f"Error iterating block: {e_inner}")
    except Exception as e:
        print(f"Error in get_loop_blocks: {e}")
        return set()
    cfg = {}
    try:
        for block in blocks:
            succs = []
            try:
                dest_iter = block.getDestinations(monitor)
                while dest_iter.hasNext():
                    try:
                        ref = dest_iter.next()
                        dest_block = ref.getDestinationBlock()
                        if dest_block is not None:
                            succs.append(dest_block)
                    except Exception as inner2:
                        print(f"Error in destination iteration: {inner2}")
                cfg[block] = succs
            except Exception as inner_e:
                print(f"Error processing block {block}: {inner_e}")
        loop_blocks = set()
        visited = set()
        rec_stack = set()

        def dfs(block):
            try:
                visited.add(block)
                rec_stack.add(block)
                for succ in cfg.get(block, []):
                    if succ not in visited:
                        dfs(succ)
                    elif succ in rec_stack:
                        loop_blocks.update(rec_stack)
                rec_stack.remove(block)
            except Exception as dfs_e:
                print(f"Error in DFS: {dfs_e}")

        for block in blocks:
            if block not in visited:
                dfs(block)
        return loop_blocks
    except Exception as e:
        print(f"Error in get_loop_blocks (CFG): {e}")
        return set()


def get_string_deobfuscation_indicators(function, instructions, listing, loop_flag, program):
    """
    Analyze a function for indicators of string deobfuscation. 

    Parameters:
        function: The function object.
        instructions (list): List of instructions in the function.
        listing: The program listing.
        loop_flag (bool): Indicates if the function contains loops.
        program: The Ghidra Program object.

    Returns:
        dict: A dictionary of boolean flags and numerical counts for various deobfuscation heuristics.
    """
    from ghidra.program.model.address import AddressSet
    indicators = {}
    try:
        # 1. Detect MOV → XOR → MOV sequence and subsequent jump.
        mov_xor_mov_found = False
        jump_found = False
        mnemonics_list = []
        for instr in instructions:
            try:
                mnem = instr.getMnemonicString().upper()
                mnemonics_list.append(mnem)
                if len(mnemonics_list) >= 3:
                    if (mnemonics_list[-3] in MOV_MNEMONICS and 
                        mnemonics_list[-2] == XOR_MNEMONIC and 
                        mnemonics_list[-1] in MOV_MNEMONICS):
                        mov_xor_mov_found = True
                if mov_xor_mov_found and mnem in JUMP_MNEMONICS:
                    jump_found = True
            except Exception as inner:
                print(f"Error processing mnemonic for indicator: {inner}")
        indicators["is_mov_xor_mov_sequence"] = mov_xor_mov_found
        indicators["is_jump_after_sequence"] = jump_found

        # 2. Detect calls to common string/memory functions.
        library_functions = ["STRLEN", "STRCPY", "SPRINTF", "MEMCPY", "STRCAT", "STRCHR", "STRNCPY"]
        library_call_detected = False
        for instr in instructions:
            try:
                if "CALL" in instr.getMnemonicString().upper():
                    instr_text = instr.toString().upper()
                    for lib in library_functions:
                        if lib in instr_text:
                            library_call_detected = True
                            break
                if library_call_detected:
                    break
            except Exception as inner:
                print(f"Error processing call instruction for library detection: {inner}")
        indicators["is_library_call_detected"] = library_call_detected

        # 3. Check for consistency of XOR immediate operands (fixed-key XOR) and compute entropy.
        xor_immediates = []
        for instr in instructions:
            try:
                if instr.getMnemonicString().upper() == XOR_MNEMONIC:
                    op1 = instr.getDefaultOperandRepresentation(1)
                    if op1 is not None and any(c.isdigit() for c in op1):
                        xor_immediates.append(op1)
            except Exception as inner:
                print(f"Error processing XOR immediate: {inner}")
        indicators["is_consistent_xor_immediate"] = (len(xor_immediates) > 0 and len(set(xor_immediates)) == 1)
        # Compute the average entropy of the XOR immediates.
        if xor_immediates:
            entropies = [compute_entropy(x) for x in xor_immediates]
            avg_entropy = sum(entropies) / len(entropies)
        else:
            avg_entropy = 0
        indicators["average_xor_immediate_entropy"] = avg_entropy
        # Flag as a low-entropy key if below threshold (arbitrarily 2.5 bits).
        indicators["is_low_entropy_key"] = (avg_entropy < 2.5) if xor_immediates else False

        # 4. Loop-based indicators: count arithmetic, bitwise shift operations and detect CMP/TEST.
        arithmetic_in_loop = 0
        bitwise_shifts_in_loop = 0
        cmp_test_in_loop = False
        if loop_flag:
            try:
                loop_blocks = get_loop_blocks(function, program)
                for block in loop_blocks:
                    try:
                        addr_set = AddressSet(block.getMinAddress(), block.getMaxAddress())
                        block_instructions = list(listing.getInstructions(addr_set, True))
                        for instr in block_instructions:
                            try:
                                mnem = instr.getMnemonicString().upper()
                                if mnem in ["CMP", "TEST"]:
                                    cmp_test_in_loop = True
                                if mnem in ["ADD", "SUB"]:
                                    arithmetic_in_loop += 1
                                if mnem in ["AND", "OR", "SHL", "SHR", "SAR", "ROL", "ROR"]:
                                    bitwise_shifts_in_loop += 1
                            except Exception as inner2:
                                print(f"Error processing loop instruction: {inner2}")
                    except Exception as inner:
                        print(f"Error processing loop block: {inner}")
            except Exception as e_loop:
                print(f"Error in loop processing: {e_loop}")
        indicators["is_cmp_or_test_in_loop"] = cmp_test_in_loop
        indicators["count_arithmetic_ops_in_loop"] = arithmetic_in_loop
        indicators["count_bitwise_shifts_in_loop"] = bitwise_shifts_in_loop

        # 5. Heuristic: Detect Base64 routines.
        is_base64_detected = False
        for instr in instructions:
            try:
                lower_instr = instr.toString().lower()
                if "base64_decode" in lower_instr or "base64_encode" in lower_instr:
                    is_base64_detected = True
                    break
            except Exception as inner:
                print(f"Error processing for Base64: {inner}")
        indicators["is_base64_detected"] = is_base64_detected

        # 6. Heuristic: Detect RC4 decryption (swap instructions with key schedule constants).
        is_rc4_decryption_detected = False
        for instr in instructions:
            try:
                mnem = instr.getMnemonicString().upper()
                if "XCHG" in mnem or "SWAP" in mnem:
                    op0 = instr.getDefaultOperandRepresentation(0)
                    if op0 is not None and ("256" in op0 or "0x100" in op0):
                        is_rc4_decryption_detected = True
                        break
            except Exception as inner:
                print(f"Error processing for RC4: {inner}")
        indicators["is_rc4_decryption_detected"] = is_rc4_decryption_detected

        # 7. Heuristic: Detect AES decryption.
        is_aes_decryption_detected = False
        for instr in instructions:
            try:
                mnem = instr.getMnemonicString().upper()
                if mnem.startswith("AESENC") or mnem.startswith("AESDEC") or \
                   mnem.startswith("AESKEYGENASSIST") or mnem.startswith("AESIMC"):
                    is_aes_decryption_detected = True
                    break
            except Exception as inner:
                print(f"Error processing for AES: {inner}")
        if not is_aes_decryption_detected:
            for instr in instructions:
                try:
                    lower_instr = instr.toString().lower()
                    if "aes_set_decrypt_key" in lower_instr or "aes_decrypt" in lower_instr:
                        is_aes_decryption_detected = True
                        break
                except Exception as inner:
                    print(f"Error processing AES call: {inner}")
        indicators["is_aes_decryption_detected"] = is_aes_decryption_detected

        # 8. Heuristic: Control Flow Complexity in small functions.
        total_instr = len(instructions)
        branch_count = 0
        indirect_call_count = 0
        for instr in instructions:
            try:
                mnem = instr.getMnemonicString().upper()
                if mnem in JUMP_MNEMONICS:
                    branch_count += 1
                if "CALL" in mnem and "*" in instr.toString():
                    indirect_call_count += 1
            except Exception as inner:
                print(f"Error processing control flow heuristic: {inner}")
        branch_density = branch_count / total_instr if total_instr > 0 else 0
        indicators["is_control_flow_flattened"] = True if total_instr < 50 and branch_density > 0.3 else False
        indicators["branch_density"] = branch_density
        indicators["count_indirect_call"] = indirect_call_count

        # 9. Heuristic: Detect mixed operations within loops.
        is_mixed_operation_loop = False
        if loop_flag:
            try:
                loop_blocks = get_loop_blocks(function, program)
                for block in loop_blocks:
                    addr_set = AddressSet(block.getMinAddress(), block.getMaxAddress())
                    block_instructions = list(listing.getInstructions(addr_set, True))
                    if len(block_instructions) == 0:
                        continue
                    mixed_ops_count = 0
                    for instr in block_instructions:
                        try:
                            mnem = instr.getMnemonicString().upper()
                            if mnem == XOR_MNEMONIC or mnem in ["ROL", "ROR", "ADD", "SUB"]:
                                mixed_ops_count += 1
                        except Exception as inner:
                            print(f"Error processing mixed operations in loop: {inner}")
                    if (mixed_ops_count / len(block_instructions)) > 0.6:
                        is_mixed_operation_loop = True
                        break
            except Exception as e_loop:
                print(f"Error processing mixed loop operations: {e_loop}")
        indicators["is_mixed_operation_loop"] = is_mixed_operation_loop

        # 10. Heuristic: Detect SIMD instructions.
        SIMD_MNEMONICS = [
            "MOVDQA", "MOVDQU", "PADD", "PSUB", "PMULHUW", "PMULLD",
            "PMULUDQ", "PADDD", "PSLLD", "PSRLD", "PUNPCKLBW", "PUNPCKLWD",
            "PUNPCKLDQ", "PALIGNR", "MULPS", "ADDPS", "SUBPS", "DIVPS",
            "ANDPS", "ORPS", "XORPS", "MOVAPS", "MOVUPS"
        ]
        simd_count = 0
        for instr in instructions:
            try:
                mnem = instr.getMnemonicString().upper()
                if mnem in SIMD_MNEMONICS:
                    simd_count += 1
            except Exception as inner:
                print(f"Error processing SIMD instruction: {inner}")
        indicators["is_simd_instruction_present"] = (simd_count > 0)
        indicators["count_simd_instruction"] = simd_count

    except Exception as e:
        print(f"Error in get_string_deobfuscation_indicators: {e}")
    return indicators


def compute_stats(metric, data):
    """
    Compute the mean, median, and standard deviation for a given metric over a list of function data.

    Parameters:
        metric (str): The key name for the metric in the data dictionary.
        data (list): A list of function data dictionaries.

    Returns:
        dict: A dictionary with keys 'mean', 'median', and 'stdev' representing the computed statistics.
    """
    try:
        values = [item[metric] for item in data if metric in item]
        if not values:
            return {"mean": 0, "median": 0, "stdev": 0}
        return {
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0
        }
    except Exception as e:
        print(f"Error in compute_stats: {e}")
        return {"mean": 0, "median": 0, "stdev": 0}
