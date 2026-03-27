arch_prtct_constants = {
  "ARCH_SET_GS": 4097,
  "ARCH_SET_FS": 4098,
  "ARCH_GET_FS": 4099,
  "ARCH_GET_GS": 4100,
  "ARCH_GET_CPUID": 4113,
  "ARCH_SET_CPUID": 4114
}
def getArchPrtctName(value):
    for name in arch_prtct_constants:
        if arch_prtct_constants[name] == value:
            return name
    return None
