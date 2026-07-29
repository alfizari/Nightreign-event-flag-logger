import frida
import sys, json

PROCESS_NAME=None
EXCLUDE_FLAGS = [
    0x7EE,
    0x989F30,
    0x3B9ACDE8,
    0x98A10C,
    0x3B9ACDEA,
    0x3B9ACDEB,
]

def set_process_name(proc_name):
    # show current running process and let them choose

    global PROCESS_NAME


    #fallback 
    PROCESS_NAME = "start_protected_game.exe"

    # or nightreign.exe

    # after choosing we will change the process name on the JS also both of them

    



def load_flags(filename):
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ";" not in line:
                continue

            flag_id, name = line.split(";", 1)
            yield int(flag_id), name


known_flags = {flag_id: name for flag_id, name in load_flags("event_flag_list.txt")}

def event_flag_trigger(flag_id, lock_state):
    try:
        session = frida.attach(PROCESS_NAME)
    except frida.ProcessNotFoundError:
        print(f"[!] Process '{PROCESS_NAME}' not found. Ensure the game is running.")
        sys.exit(1)

    with open("event_trigger.js", "r", encoding="utf-8") as f:
        script_code = f.read()

    script_code = script_code.replace("{{PROCESS_NAME}}", PROCESS_NAME)
    script = session.create_script(script_code)
    script.load()

    api = script.exports_sync

    if flag_id.lower().startswith("0x"):
        flag_id = int(flag_id, 16)
    elif any(c in "abcdefABCDEF" for c in flag_id):
        flag_id = int(flag_id, 16)
    else:
        flag_id = int(flag_id)

    response = api.set_flag(flag_id, lock_state)

    if response.get("success"):
        print(f"[+] Success! Native Return Code: {response.get('result')}")
    else:
        print(f"[!] Execution Aborted: {response.get('reason')}")

    session.detach()


def event_flag_logger():
    try:
        session = frida.attach(PROCESS_NAME)
    except frida.ProcessNotFoundError:
        print(f"[!] Process '{PROCESS_NAME}' not found. Ensure the game is running.")
        sys.exit(1)

    DATA_FILE = "event_flag_data.txt"
    seen_events = {}  # Function-local dict

    def append_to_file(line):
        with open(DATA_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def on_message(message, data):
        nonlocal seen_events

        msg_type = message.get("type")
        payload = message.get("payload", {})

        if msg_type == "send":
            payload_type = payload.get("type")

            if payload_type == "init":
                event_flag_man = payload.get("event_flag_man", "N/A")
                event_flag_start = payload.get("event_flag_start", "N/A")

                init_header = (
                    f"--- SESSION INITIALIZED ---\n"
                    f"event_flag_man: {event_flag_man} | event_flag_start: {event_flag_start}\n"
                    f"---------------------------"
                )
                append_to_file(init_header)
                print(f"Initialized: event_flag_start={event_flag_start}")

            elif payload_type == "write_event":
                item_id = payload.get("item_id")
                address = payload.get("rcx")
                bit = payload.get("r10")
                event_flag_start_val = payload.get("event_flag_start")
                lock_state = payload.get("lock_state")

                if address and event_flag_start_val:
                    try:
                        addr_int = (
                            int(address, 16) if isinstance(address, str) else address
                        )
                        start_int = (
                            int(event_flag_start_val, 16)
                            if isinstance(event_flag_start_val, str)
                            else event_flag_start_val
                        )
                        save_offset = hex(addr_int - start_int)
                    except (ValueError, TypeError) as e:
                        print(f"Error calculating offset: {e}")
                        save_offset = "N/A"

                    item_str = str(item_id) if item_id is not None else "unknown"
                    lock_str = str(lock_state) if lock_state is not None else "N/A"
                    addr_str = str(address) if address is not None else "N/A"
                    offset_str = str(save_offset) if save_offset is not None else "N/A"
                    bit_str = str(bit) if bit is not None else "N/A"

                    current_entry = (lock_str, addr_str, offset_str, bit_str)
                    if seen_events.get(item_str) == current_entry:
                        return

                    seen_events[item_str] = current_entry

                    log_line = (
                        f"ItemID: {item_str:<12} | LockState: {lock_str:<5} | "
                        f"Offset: {addr_str} | SaveOffset: {offset_str} | Bit: {bit_str}"
                    )
                    append_to_file(log_line)
                    print(f"Logged: {item_str}")
                else:
                    print(
                        f"Missing data: address={address}, event_flag_start={event_flag_start_val}"
                    )

    # Read and inject both PROCESS_NAME and EXCLUDE_FLAGS
    with open("unlock_logger.js", "r", encoding="utf-8") as f:
        script_code = f.read()

    script_code = script_code.replace("{{PROCESS_NAME}}", PROCESS_NAME)
    script_code = script_code.replace(
        "{{EXCLUDE_FLAGS}}", json.dumps(EXCLUDE_FLAGS)
    )

    script = session.create_script(script_code)
    script.on("message", on_message)
    script.load()

    print(f"Logging active. Appending output to '{DATA_FILE}'...")
    try:
        input("Press Enter to stop logging and detach...\n")
    except KeyboardInterrupt:
        pass
    finally:
        session.detach()
        print("[*] Frida session detached cleanly.")

if __name__ == "__main__":
    pass