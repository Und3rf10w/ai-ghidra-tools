# Ghidra script to patch binary bytes at a given address
# @category Claude.MCP
# @runtime Jython

import json

def output_json(data):
    """Output JSON data between markers for parsing."""
    print("===JSON_START===")
    print(json.dumps(data))
    print("===JSON_END===")

def parse_hex_bytes(hex_string):
    """
    Parse hex string into byte array.

    Supports formats:
    - "48 8b 05" - space-separated hex
    - "488b05" - continuous hex

    Returns: list of byte values (0-255)
    """
    # Remove spaces and normalize
    hex_str = hex_string.replace(" ", "").lower()

    if len(hex_str) % 2 != 0:
        raise ValueError("Hex string must have even number of characters")

    bytes_list = []
    for i in range(0, len(hex_str), 2):
        byte_str = hex_str[i:i+2]
        try:
            byte_val = int(byte_str, 16)
            if byte_val < 0 or byte_val > 255:
                raise ValueError("Byte value out of range: " + byte_str)
            bytes_list.append(byte_val)
        except ValueError:
            raise ValueError("Invalid hex byte: " + byte_str)

    return bytes_list

def run():
    """Main script entry point."""
    try:
        program = currentProgram
        if program is None:
            output_json({"status": "error", "error": "No program loaded"})
            return

        args = getScriptArgs()
        if len(args) < 2:
            output_json({
                "status": "error",
                "error": "Usage: <address> <hex_bytes>"
            })
            return

        address_str = args[0]
        hex_bytes_str = args[1]

        # Validate and parse address
        addr = toAddr(address_str)
        if addr is None:
            output_json({
                "status": "error",
                "error": "Invalid address: " + address_str
            })
            return

        # Validate and parse hex bytes
        try:
            new_bytes = parse_hex_bytes(hex_bytes_str)
        except ValueError as e:
            output_json({
                "status": "error",
                "error": "Invalid hex bytes: " + str(e)
            })
            return

        if len(new_bytes) == 0:
            output_json({
                "status": "error",
                "error": "No bytes to write"
            })
            return

        memory = program.getMemory()

        # Check if address range is valid and writable
        end_addr = addr.add(len(new_bytes) - 1)
        if not memory.contains(addr):
            output_json({
                "status": "error",
                "error": "Address not in memory: " + address_str
            })
            return

        if not memory.contains(end_addr):
            output_json({
                "status": "error",
                "error": "Address range exceeds memory bounds (trying to write %d bytes)" % len(new_bytes)
            })
            return

        block = memory.getBlock(addr)
        if block and not block.isWrite():
            output_json({
                "status": "error",
                "error": "Memory block is not writable: " + block.getName()
            })
            return

        # Read old bytes before patching
        old_bytes = []
        for i in range(len(new_bytes)):
            try:
                b = memory.getByte(addr.add(i))
                old_bytes.append(b & 0xff)
            except Exception as e:
                output_json({
                    "status": "error",
                    "error": "Failed to read old bytes at offset %d: %s" % (i, str(e))
                })
                return

        # Start a transaction for writing
        transaction_id = program.startTransaction("Patch bytes at " + address_str)
        success = False

        try:
            # Write new bytes
            for i, byte_val in enumerate(new_bytes):
                try:
                    memory.setByte(addr.add(i), byte_val)
                except Exception as e:
                    raise Exception("Failed to write byte at offset %d: %s" % (i, str(e)))

            success = True

        finally:
            program.endTransaction(transaction_id, success)

        if not success:
            output_json({
                "status": "error",
                "error": "Failed to write bytes (transaction failed)"
            })
            return

        # Verify the write by reading back
        verify_bytes = []
        for i in range(len(new_bytes)):
            b = memory.getByte(addr.add(i))
            verify_bytes.append(b & 0xff)

        # Build result
        result = {
            "status": "success",
            "address": str(addr),
            "bytes_written": len(new_bytes),
            "old_bytes": " ".join(["%02x" % b for b in old_bytes]),
            "new_bytes": " ".join(["%02x" % b for b in new_bytes]),
            "verified_bytes": " ".join(["%02x" % b for b in verify_bytes])
        }

        # Add context information
        listing = program.getListing()

        # Check if this affects an instruction
        inst = listing.getInstructionContaining(addr)
        if inst:
            result["affected_instruction"] = {
                "address": str(inst.getAddress()),
                "original": inst.toString()
            }

        # Check if in a function
        fm = program.getFunctionManager()
        func = fm.getFunctionContaining(addr)
        if func:
            result["function"] = func.getName()
            result["function_offset"] = addr.subtract(func.getEntryPoint())

        # Add memory block info
        if block:
            result["memory_block"] = block.getName()

        output_json(result)

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

run()
