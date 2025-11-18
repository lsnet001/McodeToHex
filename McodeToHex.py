#!/usr/bin/env python3

import shutil
import re
import ast
from colorama import init, Fore
import readline
init()

# -------------------------
# Config
# -------------------------
MAX_BYTES = 1_000_000  # maximum bytes accepted (1 MB)

def get_terminal_width(default=80):
    try:
        return shutil.get_terminal_size().columns
    except:
        return default

task = 0

def print_banner():
    global task
    width = get_terminal_width()

    print(Fore.GREEN + "[*]Coded by lsnet001" + Fore.BLUE)

    if task < 100:
        task += 1

    print(Fore.YELLOW + "Task", task, Fore.BLUE)

    banner = [
        r"___  ___              _    _____     _   _             ",
        r"|  \/  |             | |  |_   _|   | | | |            ",
        r"| .  . | ___ ___   __| | ___| | ___ | |_| | _____  __  ",
        r"| |\/| |/ __/ _ \ / _` |/ _ \ |/ _ \|  _  |/ _ \ \/ /  ",
        r"| |  | | (_| (_) | (_| |  __/ | (_) | | | |  __/>  <   ",
        r"\_|  |_/\\___\\___/ \__,_|\___\_/\___/\_| |_/\___/_/\_\  ",
        r"                                                       ",
        r"_______________________________________________________",
    ]

    print("")
    for line in banner:
        print(line.center(width))
    print("")

# -------------------------
# Helpers
# -------------------------
def safe_fromhex(hexstr: str) -> bytes:
    try:
        return bytes.fromhex(hexstr)
    except ValueError as e:
        raise ValueError("Invalid hex data (non-hex characters or odd length).") from e

def ascii_preview(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)

# -------------------------
# PARSER — safely parse hex, C arrays, escaped, python byte literals
# -------------------------
def parse_to_bytes(user_input: str) -> bytes:
    if not isinstance(user_input, str):
        raise ValueError("Input must be a string.")

    cleaned = user_input.strip()
    if not cleaned:
        raise ValueError("No input provided.")

    # Python bytes literal like: b"\x48\x31..."
    if cleaned.startswith("b'") or cleaned.startswith('b"'):
        try:
            val = ast.literal_eval(cleaned)
            if not isinstance(val, (bytes, bytearray)):
                raise ValueError("Provided python literal is not bytes.")
            b = bytes(val)
            if len(b) > MAX_BYTES:
                raise ValueError("Input too large.")
            return b
        except (SyntaxError, ValueError) as e:
            raise ValueError("Invalid python bytes literal.") from e

    s = cleaned
    s = s.replace("{", " ").replace("}", " ")
    s = s.replace(";", " ")
    s = s.replace(",", " ")
    s = s.replace("\\x", " ")
    s = s.replace("0x", " ").replace("0X", " ")
    s = re.sub(r"\b(unsigned|char|const|static|int|unsigned|unsigned char|buf\w*|data)\b", " ", s, flags=re.IGNORECASE)
    s = re.sub(r"[^0-9A-Fa-f\s]", " ", s)
    tokens = [t for t in s.split() if t]

    # If nothing tokenized, maybe the input was a contiguous hex string with non-hex noise removed
    if not tokens:
        hex_only = re.sub(r"[^0-9A-Fa-f]", "", cleaned)
        if not hex_only:
            raise ValueError("No hex data detected.")
        if len(hex_only) % 2 != 0:
            raise ValueError("Hex string has odd length.")
        if len(hex_only) // 2 > MAX_BYTES:
            raise ValueError("Input too large.")
        return safe_fromhex(hex_only)

    # Single token that's pure hex
    if len(tokens) == 1 and re.fullmatch(r"[0-9A-Fa-f]+", tokens[0]):
        hexstr = tokens[0]
        if len(hexstr) % 2 != 0:
            raise ValueError("Hex string has odd length.")
        if len(hexstr) // 2 > MAX_BYTES:
            raise ValueError("Input too large.")
        return safe_fromhex(hexstr)

    # Otherwise parse as individual byte tokens (1-2 hex digits)
    bytes_out = bytearray()
    for tok in tokens:
        if not re.fullmatch(r"[0-9A-Fa-f]{1,2}", tok):
            raise ValueError(f"Invalid token in input: '{tok}' (expect 1-2 hex digits)")
        val = int(tok, 16)
        if val < 0 or val > 0xFF:
            raise ValueError(f"Value out of byte range: {tok}")
        bytes_out.append(val)
        if len(bytes_out) > MAX_BYTES:
            raise ValueError("Input too large.")
    return bytes(bytes_out)

# -------------------------
# MAIN LOGIC
# -------------------------
def start():
    print_banner()

    while True:
        try:
            print(Fore.CYAN + "Select Mode:")
            print(Fore.YELLOW + "1) Normal Hex Encoding")
            print("2) Spaced Hex")
            print("3) C-Array Format")
            print("4) \\x Escaped Format")
            print("5) Raw Bytes -> Hex")
            print("6) REVERSE (hex/C-array/python-bytes → reversed)")
            print("0) Exit")
            print()

            mode = input(Fore.WHITE + "Mode: ").strip()
            print()

            if mode == "0":
                print(Fore.GREEN + "[*]Done")
                break

            # MODE 6 — REVERSE (with auto-detect for "hex-as-text" double-encode)
            if mode == "6":
                print(Fore.CYAN + "[REVERSE MODE — Convert to bytes & hex]")
                user_in = input(Fore.WHITE + "Enter bytes/hex/C-array: ")

                try:
                    original_bytes = parse_to_bytes(user_in)
                except ValueError as e:
                    print(Fore.RED + f"[!] Error: {e}")
                    continue

                # --- NEW: detect if parsed bytes are actually ASCII text that contains hex digits (double-encoded case)
                try:
                    as_text = original_bytes.decode("ascii")
                except Exception:
                    as_text = None

                if as_text:
                    # if the decoded text looks like hex digits/spaces/commas or \x sequences, try to extract and decode again
                    if re.search(r"[0-9A-Fa-f]", as_text) and re.fullmatch(r"[0-9A-Fa-f\s,\\xX]*", as_text):
                        inner_hex = re.sub(r"[^0-9A-Fa-f]", "", as_text)
                        if inner_hex:
                            # only attempt if inner_hex has even length
                            if len(inner_hex) % 2 == 0:
                                try:
                                    candidate = safe_fromhex(inner_hex)
                                    # heuristics: candidate length should be <= MAX_BYTES
                                    if 0 < len(candidate) <= MAX_BYTES:
                                        original_bytes = candidate
                                except ValueError:
                                    # leave original_bytes as-is if second decode fails
                                    pass

                # proceed normally
                reversed_bytes = original_bytes[::]
                readable = repr(reversed_bytes)
                hex_output = "".join(f"\\x{b:02x}" for b in reversed_bytes)
                ascii_preview_str = ascii_preview(reversed_bytes)

                print()
                print(Fore.GREEN + "[Human Readable Bytes]")
                print(readable)

                print()
                print(Fore.YELLOW + "[Hex Escaped Output]")
                print(hex_output)

                print()
                print(Fore.MAGENTA + "[ASCII Preview]")
                print(ascii_preview_str)

                print()
                print(Fore.MAGENTA + "[Length]")
                print(len(reversed_bytes))

                print("")
                print_banner()
                continue

            # --------------------------------------------------
            # OTHER MODES: encode user-typed text as bytes -> hex
            # (now auto-detects hex-like inputs such as \x.., 0x.., C-arrays, or contiguous hex)
            # --------------------------------------------------
            example_string = r"\x00\x00\x00"  # raw string, escaped properly
            print(Fore.WHITE + "[*]Input the machine code.. example:", Fore.RED + example_string + Fore.WHITE)
            print()

            raw_input_text = input("")

            # Heuristic: if input looks like escaped hex (\x48...), 0x-prefixed, comma-separated hex, or only hex chars/spaces
            if re.search(r"(\\x[0-9A-Fa-f]{2})|(0x[0-9A-Fa-f]{2})|^[0-9A-Fa-f\s,]+$", raw_input_text):
                # Try to parse it as hex-like using your robust parser
                try:
                    parsed_bytes = parse_to_bytes(raw_input_text)
                except ValueError as e:
                    print(Fore.RED + f"[!] Could not parse as hex/C-array: {e}")
                    # fallback: treat as plain text
                    machine_code = raw_input_text.replace("x", " ").replace("\\", "")
                    encoded_bytes = bytes(machine_code, "utf-8")
                    hex_string = encoded_bytes.hex()
                else:
                    # parsed_bytes is the correct byte sequence
                    hex_string = parsed_bytes.hex()
            else:
                # Not hex-like: keep the original behavior (treat input as text)
                machine_code = raw_input_text.replace("x", " ").replace("\\", "")
                encoded_bytes = bytes(machine_code, "utf-8")
                hex_string = encoded_bytes.hex()

            spaced_hex = " ".join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))
            c_array = ", ".join("0x" + hex_string[i:i+2] for i in range(0, len(hex_string), 2))
            escaped = "".join(f"\\x{hex_string[i:i+2]}" for i in range(0, len(hex_string), 2))

            print()


            if mode == "1":
                print(hex_string)
            elif mode == "2":
                print(spaced_hex)
            elif mode == "3":
                print("{" + c_array + "}")
            elif mode == "4":
                print(escaped)
            elif mode == "5":
                print(spaced_hex)
            else:
                print(Fore.RED + "[!] Unknown mode, choose 0-6.")

            print(Fore.YELLOW + "^^^ Results ^^^")
            print()

            print_banner()

        except (KeyboardInterrupt, EOFError):
            print("")
            print(Fore.GREEN + "[*]Done")
            break

if __name__ == "__main__":
    start()
#                                       V 1.0