import frida
import os

session = frida.attach("start_protected_game.exe")

DATA_FILE = "event_flag_data.txt"
seen_events = {}

def append_to_file(line):
    with open(DATA_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def on_message(message, data):
    global seen_events

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
                    addr_int = int(address, 16) if isinstance(address, str) else address
                    start_int = int(event_flag_start_val, 16) if isinstance(event_flag_start_val, str) else event_flag_start_val
                    save_offset = hex(addr_int - start_int)
                except (ValueError, TypeError) as e:
                    print(f"Error calculating offset: {e}")
                    save_offset = "N/A"

                # Standardize values as strings so formatting never throws TypeError
                item_str = str(item_id) if item_id is not None else "unknown"
                lock_str = str(lock_state) if lock_state is not None else "N/A"
                addr_str = str(address) if address is not None else "N/A"
                offset_str = str(save_offset) if save_offset is not None else "N/A"
                bit_str = str(bit) if bit is not None else "N/A"

                # Check for duplicates using string representation
                current_entry = (lock_str, addr_str, offset_str, bit_str)
                if seen_events.get(item_str) == current_entry:
                    return

                seen_events[item_str] = current_entry

                # Safe formatting with fallback string variables
                log_line = (
                    f"ItemID: {item_str:<12} | LockState: {lock_str:<5} | "
                    f"Offset: {addr_str} | SaveOffset: {offset_str} | Bit: {bit_str}"
                )
                append_to_file(log_line)
                print(f"Logged: {item_str}")
            else:
                print(f"Missing data: address={address}, event_flag_start={event_flag_start_val}")

with open("unlock_logger.js", "r", encoding="utf-8") as f:
    script = session.create_script(f.read())

script.on("message", on_message)
script.load()

print(f"Logging active. Appending output to '{DATA_FILE}'...")
input("Press Enter to exit...\n")


# def calculate_byte(r10, old_value=0):
#     """
#     Calculate the new byte after setting the flag.

#     r10 = v11 from the function
#     old_value = current byte value before change
#     """

#     byte_offset = r10 >> 3
#     bit = 7 - (r10 & 7)

#     new_value = old_value | (1 << bit)

#     print(f"Byte offset: {byte_offset}")
#     print(f"Bit: {bit}")
#     print(f"Old byte: {hex(old_value)}")
#     print(f"New byte: {hex(new_value)}")

#     return new_value


# # Your captured value
# R10 = 0x7

# calculate_byte(R10)