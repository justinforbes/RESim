class WinKParams():
    def __init__(self):
        self.param_version = 11
        kernel_base = 0xffff000000000000
        self.kernel_base = kernel_base & 0xFFFFFFFFFFFFFFFF
        self.current_task = None
        self.proc_ptr = None
        self.ts_next = None
        self.ts_prev = None
        self.ts_pid = None
        self.sysenter = None
        self.sysexit = None
        self.iretd = None
        self.sysret64 = None
        self.syscall_compute = None
        self.syscall_jump = None
        self.page_fault = None
        self.arm_entry = None
        self.ptr2stack = None
        self.saved_cr3 = None
        self.page_table = None

    def printParams(self):
        print('Windows Kernel parameters:')
        for k in self.__dict__.keys():
            v = self.__dict__.__getitem__(k)
            if v is not None:
                print('\t%-30s  %s' % (k, v))
    def getParamString(self):
        retval = 'Windows Kernel parameters:\n'
        for k in self.__dict__.keys():
            v = self.__dict__.__getitem__(k)
            if v is not None:
                retval = retval + '\t%-30s  %s\n' % (k, v)
        return retval
