class TraceFiles():
    class FileWatch():
        def __init__(self, path, outfile):
            self.path = path
            self.outfile = outfile
            self.fd = None
        
    def __init__(self, traceProcs, lgr):
        self.path_list = {}
        ''' only used to delete content on first use '''
        self.watched_files = []
        self.lgr = lgr
        self.open_files = {}
        self.traceProcs = traceProcs
        ''' for tracing of only FD, e.g., to ignore close '''
        self.tracing_fd = []
        ''' for including file traces in watch marks '''
        self.dataWatch = None

    def watchFile(self, path, outfile):
        self.path_list[path] = self.FileWatch(path, outfile)
        if path not in self.watched_files:
            self.lgr.debug('traceFiles open and close %s' % outfile)
            with open(outfile, 'w') as fh:
                fh.write('start of RESim copy of %s\n' % outfile) 
            self.watched_files.append(path)

    def watchFD(self, fd, outfile):
        if fd in self.open_files:
            print('FD %d already being watched' % fd)
            return
        self.open_files[fd] = self.FileWatch(None, outfile)
        self.open_files[fd].fd = fd
        with open(outfile, 'w') as fh:
                fh.write('start of RESim copy of FD %d\n' % fd) 
        self.lgr.debug('TraceFiles watchFD %d num open files %d' % (fd, len(self.open_files)))
        self.tracing_fd.append(fd)
        

    def open(self, path, fd):
        if path in self.path_list:
            self.path_list[path].fd = fd
            self.open_files[fd] = self.path_list[path]

    def close(self, fd):
        if fd not in self.tracing_fd:
            if fd in self.open_files and fd not in self.tracing_fd:
                self.open_files[fd].fd = None
                del self.open_files[fd]
                self.lgr.debug('TraceFiles close %d num open files %d'  % (fd, len(self.open_files)))
        else:
            with open(self.open_files[fd].outfile, 'a') as fh:
                fh.write('\nFile closed.\n')

    def nonull(self, the_bytes):
        retval = []
        index = 0
        #hx = ''.join('{:02x}'.format(x) for x in the_bytes)
        #print('the bytes is %s' % hx)
        for i in the_bytes:
            if i >= 32 and i<128:
                #print('got nonzero at %d' % index)
                retval.append(i)
            index += 1
        return retval 

    def write(self, pid, fd, the_bytes):
        stripped = self.nonull(the_bytes)
        if self.traceProcs is not None and len(self.path_list) > 0:
            fname = self.traceProcs.getFileName(pid, fd)
            self.lgr.debug('TraceFiles write got fname %s' % fname)
            if fname is not None and fname in self.path_list:
                file_watch = self.path_list[fname]
                with open(self.path_list[fname].outfile, 'a') as fh:
                    s = ''.join(map(chr,stripped))
                    self.lgr.debug('TraceFiles got %s from traceProcs for fd %d, writing to %s %s'  % (fname, fd, self.path_list[fname].outfile, s))
                    fh.write(s)
                    fh.flush()
                    if self.dataWatch is not None:
                        self.dataWatch.markLog(s, fname)
        
                 
        elif fd in self.open_files:
            ''' tracing fd '''
            with open(self.open_files[fd].outfile, 'a') as fh:
                s = ''.join(map(chr,stripped))
                self.lgr.debug('TraceFiles writing to %s %s'  % (self.open_files[fd].outfile, s))
                fh.write(s)
                if self.dataWatch is not None:
                    prefix = 'FD:%d' % fd
                    self.dataWatch.markLog(s, prefix)
            

    def markLogs(self, dataWatch):
        self.dataWatch = dataWatch
        self.lgr.debug('TraceFiles markLogs')
