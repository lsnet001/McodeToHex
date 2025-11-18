McodeToHex — Multi-Format Machine Code Converter

A flexible Python tool for converting between raw machine code, hex, C-arrays, escaped sequences, and Python byte literals, with intelligent auto-detection and safe parsing.
Designed for reverse-engineering, exploit development training, binary analysis practice, and general byte-format conversions.

This tool does not execute shellcode — it only converts bytes.
But if user input is over terminal character limit, then part of shell code could run.. so beware!!
Im not liable for any damage or reconstructed purposes.

Use at own risks!


Features

Convert machine code or hex input into:
	Normal hex (4831f6…)
	Spaced hex (48 31 f6 …)
	C-Array format ({0x48, 0x31, 0xf6, ...})
	\x-escaped format (\x48\x31\xf6…)

Accepts many input styles:
	\x48\x31\xf6…
	0x48, 0x31, 0xf6
	{0x48,0x31,0xf6}
	4831f6…
	b"\x48\x31…" (Python bytes literal)

Cleans noisy input (spaces, commas, braces, C code fragments, etc.)

Reverse Mode to decode incoming hex/C-array/escaped formats and show:
	raw bytes
	hex-escaped output
	ASCII preview
	length

Handles up to 1MB of bytes safely(Roughly one million Bytes.)

Fully colorized terminal UI (via colorama)

Requirements:
	Python 3.8+
	colorama

Usage
	Run the tool:
		python3 McodeToHex.py

Input examples
	All of the following are valid inputs:
		\x48\x31\xf6\x56\x48
		0x48, 0x31, 0xf6, 0x56
		{0x48, 0x31, 0xf6, 0x56}
		4831f656
		b"\x48\x31\xf6\x56"

Error Handling
	The script tries to protect you by:
		Rejecting invalid hex characters
		Rejecting odd-length hex strings
		Rejecting non-byte-range integers
		Rejecting inputs larger than 1 MB
		Falling back cleanly when parsing fails
		Detecting when hex bytes are accidentally encoded as text

Errors are displayed in red and do not crash the tool.

MIT License

Copyright (c) 2025 lsnet001

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
