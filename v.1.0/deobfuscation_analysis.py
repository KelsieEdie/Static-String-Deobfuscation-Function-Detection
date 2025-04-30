"""
File Name: Static-String-Deobfuscation-Function-Detection/v.1.0/deobfuscation_analysis.py
Purpose: Main analysis script for the deobfuscation candidate finder.
         It imports helper functions from deobfuscation_analysis_helpers.py, performs error checking,
         computes metrics and z-scores (for all measured values including the additional heuristics),
         prints the functions with the highest z-score per metric, and outputs the overall analysis to a JSON file.
Date Last Modified: 15 April 2025
Author: Kelsie A. Edie (kelsie_edie@brown.edu)
"""

import json
import sys
import argparse

from deobfuscation_analysis_helpers import (
    count_call_instructions,
    count_global_references,
    count_non_zeroing_xor,
    count_xref,
    is_loop_detected,
    build_call_graph,
    compute_stats,
    get_loop_blocks,
    get_string_deobfuscation_indicators,
)

import pyhidra
pyhidra.start(True)
import ghidra
from ghidra.program.util import GhidraProgramUtilities
from ghidra.program.model.address import AddressSet


def main(filename, project_location, projectname):
    """
    Main function to perform deobfuscation analysis on a binary.

    Parameters:
        filename (str): The path to the binary file to analyze.
        project_location (str): The location of the Ghidra project.
        projectname (str): The name of the Ghidra project.

    Returns:
        None. The analysis results are printed to the terminal and saved to a JSON output file.
    """
    try:
        with pyhidra.open_program(filename, project_name=projectname, project_location=project_location) as flat_api:
            program = flat_api.getCurrentProgram()
            if GhidraProgramUtilities.shouldAskToAnalyze(program):
                flat_api.analyzeAll(program)

            from ghidra.program.flatapi import FlatProgramAPI
            api = FlatProgramAPI(program)
        
            memory = program.getMemory()
            listing = program.getListing()
            function_manager = program.getFunctionManager()
            refManager = program.getReferenceManager()

            # Gather file metadata.
            file_name = filename
            file_type = program.getExecutableFormat() if hasattr(program, "getExecutableFormat") else "Unknown"
            functions = list(function_manager.getFunctions(True))
            total_functions = len(functions)
            print("[*] File Metadata:")
            print(f"    File Name   : {file_name}")
            print(f"    File Type   : {file_type}")
            print(f"    Total Funcs : {total_functions}\n")

            analysis_results = []
            func_info = {}  # Mapping from function address to information dictionary
            print("[*] Starting function analysis...")
            for function in functions:
                try:
                    func_data = {}
                    entry_str = function.getEntryPoint().toString()
                    func_identifier = f"{function.getName()} @ {entry_str}"
                    func_data["identifier"] = func_identifier
                    func_info[entry_str] = {"name": function.getName(), "address": entry_str}
                    
                    # Tried to force the full disassembly of the entire function body
                    body = function.getBody()
                    addrIter = body.getAddresses(True)
                    for addr in addrIter:
                        # If Ghidra hasn't made an Instruction here yet, then force it to do it - this does not seem like it works. 
                        if listing.getInstructionAt(addr) is None:
                            api.disassemble(addr)
                    instructions = list(listing.getInstructions(body, True))

                    entry_str = function.getEntryPoint().toString()
                    # instructions = list(listing.getInstructions(function.getBody(), True))
                    func_data["count_instruction"] = len(instructions)
                    reads, writes = count_global_references(function, listing, refManager, memory)
                    func_data["count_global_data_reads"] = reads
                    func_data["count_global_data_writes"] = writes

                    func_data["count_non_zeroing_xor"] = count_non_zeroing_xor(instructions)
                    func_data["count_xref"] = count_xref(function, refManager)
                    func_data["count_callees"] = count_call_instructions(function, listing)

                    loop_flag = is_loop_detected(function, program)
                    func_data["is_loop_detected"] = loop_flag

                    # Loop-scoped metrics.
                    loop_xor_count = 0
                    loop_arithmetic_count = 0
                    loop_decryption_pattern_count = 0  # Placeholder for future enhancement.
                    if loop_flag:
                        loop_blocks = get_loop_blocks(function, program)
                        for block in loop_blocks:
                            try:
                                addr_set = AddressSet(block.getMinAddress(), block.getMaxAddress())
                                block_instructions = list(listing.getInstructions(addr_set, True))
                                loop_xor_count += count_non_zeroing_xor(block_instructions)

                            except Exception as inner_loop:
                                print(f"Error processing loop block: {inner_loop}")
                        func_data["count_loop_non_zeroing_xor"] = loop_xor_count
                        func_data["count_loop_decryption_pattern"] = loop_decryption_pattern_count
                    else:
                        func_data["count_loop_non_zeroing_xor"] = 0
                        func_data["count_loop_decryption_pattern"] = 0

                    # Obtain string deobfuscation indicators.
                    indicators = get_string_deobfuscation_indicators(function, instructions, listing, loop_flag, program)
                    func_data["string_deobfuscation_indicators"] = indicators

                    analysis_results.append(func_data)
                except Exception as func_e:
                    print(f"Error processing function {function.getName()}: {func_e}")

            print(f"[*] Processed {len(analysis_results)} functions.")
            print("[*] Reconstructing call graph...")
            call_graph = build_call_graph(program, func_info)

            for func in analysis_results:
                for key, value in func.get("string_deobfuscation_indicators", {}).items():
                    if isinstance(value, bool):
                        func[key] = int(value)
                    else:
                        func[key] = value

            non_indicator_metrics = [
                "count_global_data_reads", "count_global_data_writes", "count_non_zeroing_xor",
                "count_xref", "count_callees", "count_instruction",
                "count_loop_non_zeroing_xor", "count_loop_decryption_pattern"
            ]

            indicator_metrics = set()
            for func in analysis_results:
                for key in func.get("string_deobfuscation_indicators", {}).keys():
                    indicator_metrics.add(key)
            indicator_metrics = list(indicator_metrics)

            metrics = non_indicator_metrics + indicator_metrics

            # Compute overall statistics for all metrics.
            overall_stats = {}
            for m in metrics:
                overall_stats[m] = compute_stats(m, analysis_results)

            # Compute z-scores for every metric.
            for func in analysis_results:
                for m in metrics:
                    try:
                        stdev = overall_stats[m]["stdev"]
                        if stdev > 0:
                            func[m + "_zscore"] = (func[m] - overall_stats[m]["mean"]) / stdev
                        else:
                            func[m + "_zscore"] = 0
                    except Exception as score_e:
                        print(f"Error computing zscore for {m} in {func['identifier']}: {score_e}")
                        func[m + "_zscore"] = 0

            # Identify functions with the highest absolute z-score for each metric.
            highest_zscore_functions = {}
            for m in metrics:
                max_abs_z = 0
                top_funcs = []
                for func in analysis_results:
                    try:
                        current_z = abs(func[m + "_zscore"])
                        if current_z > max_abs_z:
                            max_abs_z = current_z
                            top_funcs = [func]
                        elif current_z == max_abs_z:
                            top_funcs.append(func)
                    except Exception as inner:
                        print(f"Error processing zscore for function {func['identifier']}: {inner}")
                highest_zscore_functions[m] = top_funcs

            # Consolidate highest zscores for further analysis
            highest_zscores_output = {}
            for m in metrics:
                if highest_zscore_functions.get(m) and abs(highest_zscore_functions[m][0][m + "_zscore"]) != 0:
                    highest_zscores_output[m] = []
                    for func in highest_zscore_functions[m]:
                        highest_zscores_output[m].append({
                            "identifier": func["identifier"],
                            m + "_zscore": round(func[m + "_zscore"], 2)
                        })

            # JSON Output.
            output = {
                "file_metadata": {
                    "file_name": file_name,
                    "file_type": file_type,
                    "total_functions": total_functions
                },
                "overall_stats": overall_stats,
                "highest_zscores": highest_zscores_output,
                "functions": analysis_results,
                "call_graph": call_graph
            }

            output_filename = f"{projectname}_analysis_results_v1+.json"
            try:
                with open(output_filename, "w") as f:
                    json.dump(output, f, indent=4)
                print(f"[*] Analysis complete. Results saved to {output_filename}.")
            except Exception as file_e:
                print(f"Error writing output file: {file_e}")
    except Exception as e:
        print(f"Error in main analysis: {e}")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Deobfuscation Candidate Finder Analysis Script."
    )
    parser.add_argument(
        "--filename",
        required=True,
        help="Absolute path to the binary file to analyze."
    )
    parser.add_argument(
        "--project-location",
        required=True,
        help="Absolute path to the Ghidra project location."
    )
    parser.add_argument(
        "--projectname",
        required=True,
        help="Name of the Ghidra project."
    )
    args = parser.parse_args()
    main(args.filename, args.project_location, args.projectname)

