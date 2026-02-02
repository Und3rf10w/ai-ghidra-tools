# Ghidra script to search for byte patterns/hex signatures
# @category Claude.MCP
# @runtime Jython

import json
from jarray import array

def output_json(data):
    """Output JSON data between markers for parsing."""
    print("===JSON_START===")
    print(json.dumps(data))
    print("===JSON_END===")

def parse_byte_pattern(pattern_str):
    """
    Parse a byte pattern string into bytes and mask.

    Supports formats:
    - "48 8b 05" - space-separated hex
    - "488b05" - continuous hex
    - "48 ?? 05" - with wildcards
    - "48 8b ?5" - partial wildcards

    Returns: (bytes_list, mask_list) where mask is 0xff for exact match, 0x00 for wildcard
    """
    # Remove spaces and normalize
    pattern = pattern_str.replace(" ", "").lower()

    if len(pattern) % 2 != 0:
        raise ValueError("Pattern must have even number of hex characters")

    bytes_list = []
    mask_list = []

    for i in range(0, len(pattern), 2):
        byte_str = pattern[i:i+2]

        if byte_str == "??":
            bytes_list.append(0)
            mask_list.append(0x00)
        elif "?" in byte_str:
            # Partial wildcard (e.g., "?5" or "4?")
            if byte_str[0] == "?":
                bytes_list.append(int(byte_str[1], 16))
                mask_list.append(0x0f)
            else:
                bytes_list.append(int(byte_str[0], 16) << 4)
                mask_list.append(0xf0)
        else:
            bytes_list.append(int(byte_str, 16))
            mask_list.append(0xff)

    return bytes_list, mask_list

def run():
    """Main script entry point."""
    try:
        program = currentProgram
        if program is None:
            output_json({"status": "error", "error": "No program loaded"})
            return

        args = getScriptArgs()
        if not args:
            output_json({
                "status": "error",
                "error": "Usage: <byte_pattern> [max_results] [start_address] [end_address]"
            })
            return

        pattern_str = args[0]
        max_results = int(args[1]) if len(args) > 1 else 100
        start_addr_str = args[2] if len(args) > 2 else None
        end_addr_str = args[3] if len(args) > 3 else None

        try:
            bytes_list, mask_list = parse_byte_pattern(pattern_str)
        except ValueError as e:
            output_json({"status": "error", "error": "Invalid pattern: " + str(e)})
            return

        # Convert to Java byte arrays
        bytes_array = array([b if b < 128 else b - 256 for b in bytes_list], 'b')
        mask_array = array([m if m < 128 else m - 256 for m in mask_list], 'b')

        memory = program.getMemory()

        # Determine search range
        if start_addr_str:
            start_addr = toAddr(start_addr_str)
        else:
            start_addr = memory.getMinAddress()

        if end_addr_str:
            end_addr = toAddr(end_addr_str)
        else:
            end_addr = memory.getMaxAddress()

        if start_addr is None or end_addr is None:
            output_json({"status": "error", "error": "Invalid address range"})
            return

        # Search for pattern
        results = []
        listing = program.getListing()
        fm = program.getFunctionManager()

        search_addr = start_addr
        while search_addr is not None and len(results) < max_results:
            if search_addr.compareTo(end_addr) > 0:
                break

            # Search for the pattern
            found_addr = memory.findBytes(
                search_addr,
                bytes_array,
                mask_array,
                True,  # forward
                None   # monitor
            )

            if found_addr is None or found_addr.compareTo(end_addr) > 0:
                break

            # Get context for the match
            result_info = {
                "address": str(found_addr),
                "offset": found_addr.getOffset()
            }

            # Check if in a function
            func = fm.getFunctionContaining(found_addr)
            if func:
                result_info["function"] = func.getName()
                result_info["function_offset"] = found_addr.subtract(func.getEntryPoint())

            # Check if it's an instruction
            inst = listing.getInstructionAt(found_addr)
            if inst:
                result_info["instruction"] = inst.toString()

            # Get the actual bytes at this location
            actual_bytes = []
            for i in range(len(bytes_list)):
                try:
                    b = memory.getByte(found_addr.add(i))
                    actual_bytes.append("%02x" % (b & 0xff))
                except:
                    actual_bytes.append("??")
            result_info["matched_bytes"] = " ".join(actual_bytes)

            # Get memory block info
            block = memory.getBlock(found_addr)
            if block:
                result_info["memory_block"] = block.getName()

            results.append(result_info)

            # Move to next address
            search_addr = found_addr.add(1)

        output_json({
            "status": "success",
            "pattern": pattern_str,
            "pattern_length": len(bytes_list),
            "search_range": {
                "start": str(start_addr),
                "end": str(end_addr)
            },
            "result_count": len(results),
            "truncated": len(results) >= max_results,
            "matches": results
        })

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

run()
