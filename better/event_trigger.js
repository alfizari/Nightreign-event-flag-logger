const processName = "{{PROCESS_NAME}}";
const base = Process.getModuleByName(processName).base;

// Native function definition
const setEventFlag = new NativeFunction(
    base.add(0x60D330),
    'int',                       
    ['pointer', 'uint32', 'int']  // Arguments: [RCX, RDX, R8]
);

rpc.exports = {
    setFlag: function (flagId, lockState) {
        const globalPtrAddr = base.add(0x3C115A8);
        const eventFlagMan = globalPtrAddr.readPointer();

        if (eventFlagMan.isNull()) {
            return { success: false, reason: "EventFlagMan global pointer is NULL" };
        }


        try {
            const res = setEventFlag(eventFlagMan, flagId, lockState);
            return { success: true, result: res };
        } catch (err) {
            return { success: false, reason: err.message };
        }
    }
};