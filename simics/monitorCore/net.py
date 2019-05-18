import pickle
import os
SOCKET      =1 
BIND        =2
CONNECT     =3
LISTEN      =4
ACCEPT      =5
GETSOCKNAME =6
GETPEERNAME =7
SOCKETPAIR  =8
SEND        =9
RECV        =10
SENDTO      =11
RECVFROM    =12
SHUTDOWN    =13
SETSOCKOPT  =14
GETSOCKOPT  =15
SENDMSG     =16
RECVMSG     =17
ACCEPT4     =18

callname = ['dumb', 'SOCKET', 'BIND', 'CONNECT', 'LISTEN', 'ACCEPT', 'GETSOCKNAME', 'GETPEERNAME', 'SOCKETPAIR', 'SEND', 'RECV', 'SENDTO' , 'RECVFROM',   
    'SHUTDOWN' , 'SETSOCKOPT', 'GETSOCKOPT', 'SENDMSG', 'RECVMSG', 'ACCEPT4']

SOCK_STREAM     = 1
SOCK_DGRAM      = 2
SOCK_RAW        = 3
SOCK_RDM        = 4
SOCK_SEQPACKET  = 5
SOCK_DCCP       = 6
SOCK_PACKET     = 10

socktype = ['dumb', 'SOCK_STREAM', 'SOCK_DGRAM', 'SOCK_RAW', 'SOCK_RDM', 'SOCK_SEQPACKET', 'SOCK_DCCP', 'UNUNSED1', 'UNUSED2', 'UNUSED3', 'SOCK_PACKET']

SOCK_TYPE_MASK = 0xf
AF_LOCAL = 1
AF_INET = 2
domaintype = [ 'AF_UNSPEC', 'AF_LOCAL', 'AF_INET', 'AF_AX25', 'AF_IPX', 'AF_APPLETALK', 'AF_NETROM', 'AF_BRIDGE',
'AF_ATMPVC', 'AF_X25', 'AF_INET6', 'AF_ROSE', 'AF_DECnet', 'AF_NETBEUI', 'AF_SECURITY', 'AF_KEY', 'AF_NETLINK']

FIONBIO = 0x5421
FIONREAD = 0x541B

F_DUPFD = 0 

O_NONBLOCK  =   0x00004000
O_CLOEXEC   =   0x02000000        



class NetInfo():
    def __init__(self, ip, mask, broadcast, dev, label):
        self.ip = ip
        self.mask = mask
        self.broadcast = broadcast
        self.dev = dev
        self.label = label 
 
class NetAddresses():
    def __init__(self, lgr):
        self.ipv4_addrs = []
        self.net_commands = []
        self.lgr = lgr 
    def add(self, ip, mask, broadcast, dev, label):
        info = NetInfo(ip, mask, broadcast, dev, label)
        self.ipv4_addrs.append(info)
    def checkNet(self, prog, args):
        if '/bin/ip addr add' in args:
            self.lgr.debug('NetAddresses checkNet found net info %s' % args) 
            self.net_commands.append(args)
        elif 'ifconfig' in args:
            self.lgr.debug('NetAddresses checkNet found net info %s' % args) 
            self.net_commands.append(args)

    def getCommands(self):
        return self.net_commands

    def pickleit(self, net_file):
        pickle.dump( self.net_commands, open( net_file, "wb" ) )

    def loadfile(self, net_file):
        if os.path.isfile(net_file):
            self.net_commands = pickle.load( open(net_file, 'rb') ) 
        else:
            self.lgr.debug('no net file %s for checkpoint load' % net_file)

class SockStruct():
    def __init__(self, cpu, params, mem_utils, fd=None):
        self.length = 0
        self.flags = 0
        if fd is None:
            self.fd = mem_utils.readWord32(cpu, params)
            self.length = mem_utils.readWord32(cpu, params+8)
            self.flags = mem_utils.readWord32(cpu, params+12)
            self.addr = mem_utils.readWord32(cpu, params+4)
        else:
            self.fd = fd
            #self.addr = mem_utils.readWord32(cpu, params)
            self.addr = params
        self.port = None
        self.sin_addr = None
        self.sa_data = None
        self.sa_family = None
        try:
            self.sa_family = mem_utils.readWord16(cpu, self.addr) 
        except:
            return
        if self.sa_family == 1:
            self.sa_data = mem_utils.readString(cpu, self.addr+2, 256)
        elif self.sa_family == 2:
            self.port = mem_utils.readWord16le(cpu, self.addr+2)
            self.sin_addr = mem_utils.readWord32(cpu, self.addr+4)

    def famName(self):
        if self.sa_family is not None and self.sa_family < len(domaintype):
            return domaintype[self.sa_family]
        else:
            return None

    def dottedIP(self):
      if self.sin_addr is None:
          return self.famName()
      "Convert 32-bit integer to dotted IPv4 address."
      return ".".join(map(lambda n: str(self.sin_addr>>n & 0xFF), [0,8,16,24]))

    def dottedPort(self):
        return '%s:%s' % (self.dottedIP(), self.port)

    def getName(self):
        if self.sa_family == 1:
            return self.sa_data
        elif self.sa_family == 2:
            name = '%s:%s' % (self.dottedIP(), self.port)
            return name
        else:
            return None

    def isRoutable(self):
        if self.sa_family == 2:
            ip = self.dottedIP()
            if not ip.startswith('0.0.') and not ip.startswith('127.'):
                return True
        return False

    def addressInfo(self):
        ''' for use in printing traces '''
        flag = ''
        if self.isRoutable():
            flag = 'ROUTABLE IP'
        return flag

    def getString(self):
        if self.sa_family is None:
            retval = ('FD: %d sa_family unknown' % (self.fd))
        elif self.sa_family == 1:
            retval = ('FD: %d sa_family: %s  sa_data: %s' % (self.fd, self.famName(), self.sa_data))
        elif self.sa_family == 2:
            retval = ('FD: %d sa_family: %s  address: %s:%d' % (self.fd, self.famName(), self.dottedIP(), self.port))
        else:
            retval = ('FD: %d sa_family: %s  TBD' % (self.fd, self.famName()))
        return retval

class Iovec():
    def __init__(self, base, length):
        self.base = base
        self.length = length
class Msghdr():
    '''
           struct iovec {                    /* Scatter/gather array items */
               void  *iov_base;              /* Starting address */
               size_t iov_len;               /* Number of bytes to transfer */
           };

           struct msghdr {
               void         *msg_name;       /* optional address */
               socklen_t     msg_namelen;    /* size of address */
               struct iovec *msg_iov;        /* scatter/gather array */
               size_t        msg_iovlen;     /* # elements in msg_iov */
               void         *msg_control;    /* ancillary data, see below */
               size_t        msg_controllen; /* ancillary data buffer len */
               int           msg_flags;      /* flags on received message */
           };
    '''

    def __init__(self, cpu, mem_utils, msghdr_address):
        self.msg_name = mem_utils.readPtr(cpu, msghdr_address) 
        self.msg_namelen = mem_utils.readPtr(cpu, msghdr_address+mem_utils.WORD_SIZE) 
        self.msg_iov = mem_utils.readPtr(cpu, msghdr_address+2*mem_utils.WORD_SIZE) 
        self.msg_iovlen = mem_utils.readPtr(cpu, msghdr_address+3*mem_utils.WORD_SIZE) 
        self.msg_control = mem_utils.readPtr(cpu, msghdr_address+4*mem_utils.WORD_SIZE) 
        self.msg_controllen = mem_utils.readPtr(cpu, msghdr_address+5*mem_utils.WORD_SIZE) 
        self.flags = mem_utils.readPtr(cpu, msghdr_address+6*mem_utils.WORD_SIZE) 
        self.cpu = cpu
        self.mem_utils = mem_utils

    def getIovec(self):
        retval = []
        iov_size = 2*self.mem_utils.WORD_SIZE
        iov_addr = self.msg_iov
        for i in range(self.msg_iovlen):
            base = self.mem_utils.readPtr(self.cpu, iov_addr)
            length = self.mem_utils.readPtr(self.cpu, iov_addr+self.mem_utils.WORD_SIZE)
            retval.append(Iovec(base, length)) 
            iov_addr = iov_addr+iov_size
        return retval

    def getString(self):
        retval = 'msg_name 0x%x  msg_namelen: %d  msg_iov: 0x%x  msg_iovlen: %d  msg_control: 0x%x msg_controllen %d flags 0x%x' % (self.msg_name,
             self.msg_namelen, self.msg_iov, self.msg_iovlen, self.msg_control, self.msg_controllen, self.flags)
        iov_size = 2*self.mem_utils.WORD_SIZE
        iov_addr = self.msg_iov
        iov_string = ''
        for i in range(self.msg_iovlen):
            base = self.mem_utils.readPtr(self.cpu, iov_addr)
            length = self.mem_utils.readPtr(self.cpu, iov_addr+self.mem_utils.WORD_SIZE)
            iov_string = iov_string+'\n\tbase: 0x%x  length: %d' % (base, length) 
            iov_addr = iov_addr+iov_size
        retval = retval + iov_string    
        return retval
