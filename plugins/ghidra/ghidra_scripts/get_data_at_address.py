# Ghidra script to read data at an address with a given type
# @category Claude.MCP
# @runtime Jython

import json

def output_json(data):
    """Output JSON data between markers for parsing."""
    print("===JSON_START===")
    print(json.dumps(data))
    print("===JSON_END===")

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
                "error": "Usage: <address> [length|type] [format]"
            })
            return

        address_str = args[0]
        length_or_type = args[1] if len(args) > 1 else "32"
        format_type = args[2] if len(args) > 2 else "hex"

        addr = toAddr(address_str)
        if addr is None:
            output_json({"status": "error", "error": "Invalid address: " + address_str})
            return

        memory = program.getMemory()
        listing = program.getListing()
        dtm = program.getDataTypeManager()

        result = {
            "status": "success",
            "address": str(addr)
        }

        # Check if a data type was specified
        data_types = {
            "byte": 1, "char": 1,
            "short": 2, "word": 2,
            "int": 4, "dword": 4, "long": 4, "float": 4,
            "longlong": 8, "qword": 8, "double": 8,
            "pointer": program.getDefaultPointerSize()
        }

        if length_or_type.lower() in data_types:
            # Read as a specific type
            type_name = length_or_type.lower()
            length = data_types[type_name]

            raw_bytes = []
            for i in range(length):
                try:
                    b = memory.getByte(addr.add(i))
                    raw_bytes.append(b & 0xff)
                except:
                    raw_bytes.append(0)

            result["type"] = type_name
            result["length"] = length
            result["bytes"] = " ".join(["%02x" % b for b in raw_bytes])

            # Interpret the value based on type
            if type_name in ["byte", "char"]:
                result["value"] = raw_bytes[0]
                if 32 <= raw_bytes[0] < 127:
                    result["char"] = chr(raw_bytes[0])
            elif type_name in ["short", "word"]:
                # Little-endian by default
                result["value"] = raw_bytes[0] | (raw_bytes[1] << 8)
                result["value_signed"] = result["value"] if result["value"] < 0x8000 else result["value"] - 0x10000
            elif type_name in ["int", "dword", "long"]:
                result["value"] = raw_bytes[0] | (raw_bytes[1] << 8) | (raw_bytes[2] << 16) | (raw_bytes[3] << 24)
                result["value_signed"] = result["value"] if result["value"] < 0x80000000 else result["value"] - 0x100000000
            elif type_name in ["longlong", "qword"]:
                value = 0
                for i in range(8):
                    value |= raw_bytes[i] << (i * 8)
                result["value"] = value
            elif type_name == "float":
                import struct
                result["value"] = struct.unpack('<f', bytes(bytearray(raw_bytes)))[0]
            elif type_name == "double":
                import struct
                result["value"] = struct.unpack('<d', bytes(bytearray(raw_bytes)))[0]
            elif type_name == "pointer":
                value = 0
                for i in range(length):
                    value |= raw_bytes[i] << (i * 8)
                result["value"] = "0x%x" % value
                # Try to resolve what the pointer points to
                ptr_addr = toAddr("0x%x" % value)
                if ptr_addr is not None:
                    func = program.getFunctionManager().getFunctionAt(ptr_addr)
                    if func:
                        result["points_to"] = {"type": "function", "name": func.getName()}
                    else:
                        symbol = program.getSymbolTable().getPrimarySymbol(ptr_addr)
                        if symbol:
                            result["points_to"] = {"type": str(symbol.getSymbolType()), "name": symbol.getName()}

        else:
            # Read raw bytes
            try:
                length = int(length_or_type)
            except:
                length = 32

            # Cap at reasonable limit
            length = min(length, 4096)

            raw_bytes = []
            for i in range(length):
                try:
                    b = memory.getByte(addr.add(i))
                    raw_bytes.append(b & 0xff)
                except:
                    break

            result["length"] = len(raw_bytes)

            if format_type == "hex":
                result["bytes"] = " ".join(["%02x" % b for b in raw_bytes])
            elif format_type == "ascii":
                result["bytes"] = " ".join(["%02x" % b for b in raw_bytes])
                ascii_str = ""
                for b in raw_bytes:
                    if 32 <= b < 127:
                        ascii_str += chr(b)
                    else:
                        ascii_str += "."
                result["ascii"] = ascii_str
            elif format_type == "string":
                # Try to read as null-terminated string
                string_bytes = []
                for b in raw_bytes:
                    if b == 0:
                        break
                    string_bytes.append(b)
                try:
                    result["string"] = bytes(bytearray(string_bytes)).decode('utf-8')
                except:
                    result["string"] = bytes(bytearray(string_bytes)).decode('latin-1')
                result["bytes"] = " ".join(["%02x" % b for b in string_bytes])

        # Check what's defined at this address
        data = listing.getDataAt(addr)
        if data:
            result["defined_data"] = {
                "type": str(data.getDataType()),
                "value": str(data.getValue()) if data.getValue() else None
            }

        inst = listing.getInstructionAt(addr)
        if inst:
            result["instruction"] = inst.toString()

        # Get memory block info
        block = memory.getBlock(addr)
        if block:
            result["memory_block"] = {
                "name": block.getName(),
                "permissions": {
                    "read": block.isRead(),
                    "write": block.isWrite(),
                    "execute": block.isExecute()
                }
            }

        output_json(result)

    except Exception as e:
        import traceback
        output_json({
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })

run()
