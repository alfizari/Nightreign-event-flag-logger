const base = Process.getModuleByName("start_protected_game.exe").base;

let currentFlag = null;
let currentLockState = null;
let event_flag_start = null;
let event_flag_man = null;

const globalPtrAddr = base.add(0x3C115A8);
const value = globalPtrAddr.readPointer();
event_flag_start = value.add(0x28).readPointer();
event_flag_man = value;

send({
    type: "init",
    event_flag_man: event_flag_man.toString(),
    event_flag_start: event_flag_start.toString(),
});

Interceptor.attach(base.add(0x60D330), {
    onEnter() {
        const rdx = this.context.rdx.toUInt32();

        if (rdx === 0x7EE || rdx === 0x989f30 || rdx === 0x3b9acde8 || rdx === 0x98a10c || rdx === 0x3b9acdea || rdx === 0x3b9acdeb) {
            currentFlag = null;
            currentLockState = null;
            return;
        }

        currentFlag = rdx;
        currentLockState = this.context.r8.toString();

        console.log("rcx: " + this.context.rcx.toString() + " item_id: 0x" + rdx.toString(16) + " lock_state: " + currentLockState);
    }
});

Interceptor.attach(base.add(0x60D3C3), {
    onEnter() {
        // Skip if currentFlag was ignored by filter
        if (currentFlag === null) return;

        const rcx = this.context.rcx;

        send({
            type: "write_event",
            item_id: "0x" + currentFlag.toString(16),
            rcx: rcx.toString(),
            r10: this.context.r10.toString(),
            lock_state: currentLockState ? currentLockState : "N/A", // Fallback to string if null
            event_flag_start: event_flag_start.toString(),
            event_flag_man: event_flag_man.toString(),
        });
    }
});

console.log("Hooks installed");