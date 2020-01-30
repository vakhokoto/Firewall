#!/usr/bin/env python

import struct
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import random

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

IP_DB_FILENAME = 'geoipdb.txt'
TCP, UDP, ICMP, IN = 6, 17, 1, 1
TYPE_A, TYPE_AAAA = 1, 28
SERVER_IP = '169.229.49.130'

# Log file
outFile = open('http.log', 'a')

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        self.ipDB = readIPDB()
        self.rules = readRules(config['rule'], self.ipDB)
        rules, httprules = [], []
        for rule in self.rules:
            if rule.verdict == 'log':
                httprules.append(rule)
            else:
                rules.append(rule)
            
        self.rules = rules
        self.httprules = httprules

        print 'I\'m gonna catch you!'

    def _dnsDispatch(self, pkt, pkt_dir, qcode):
        if qcode == TYPE_AAAA:
            return
        fmt = struct.Struct('!B')
        length, = fmt.unpack(pkt[:1])
        length = length & ((1 << 4) - 1)
        srcip, dstip, ptype, newpkt = readIPPkt(pkt)
        fmt = struct.Struct('!H H')
        srcport, dstport = fmt.unpack(pkt[length * 4:length * 4 + 4])
        temp = srcip
        srcip, dstip = dstip, temp
        d = (srcip, dstip)
        fmt = struct.Struct('!I I')
        packedIP = fmt.pack(*d)
        temp = srcport
        srcport, dstport = dstport, temp
        dnspkt = makeDnsPkt(pkt[length * 4 + 8:], qcode)
        totalLen = length * 4 + 8 + len(dnspkt)
        dat = pkt[:2] + struct.pack('!H', *(totalLen, )) + \
            pkt[4:10] + packedIP + pkt[20:length * 4]
        ipchecksum = checksum(dat)
        dat = packedIP + struct.pack('!B B H', *(0, UDP, totalLen - length * 4)) + \
            struct.pack('!H H', *(srcport, dstport)) + struct.pack('!H', *(totalLen - length * 4, )) + dnspkt
        udpchecksum = checksum(dat)
        d = (srcport, dstport, totalLen - length * 4, udpchecksum)
        response = pkt[:2] + struct.pack('!H', *(totalLen, )) + \
            pkt[4:10] + struct.pack('!H', *(ipchecksum,)) + packedIP + pkt[20:length * 4] + \
                struct.pack('!H H H H', *d) + dnspkt
        self.iface_int.send_ip_packet(response)



    def _tcpForward(self, pkt, pkt_dir):
        fmt = struct.Struct('!B')
        length, = fmt.unpack(pkt[:1])
        length = length & ((1 << 4) - 1)
        srcip, dstip, ptype, newpkt = readIPPkt(pkt)
        fmt = struct.Struct('!H H')
        srcport, dstport = fmt.unpack(pkt[length * 4:length * 4 + 4])
        if pkt_dir == PKT_DIR_OUTGOING:
            temp = srcip
            srcip, dstip = dstip, temp
            temp = srcport
            srcport, dstport = dstport, temp
        d = (srcip, dstip)
        fmt = struct.Struct('!I I')
        packedIP = fmt.pack(*d)
        dat = pkt[:2] + struct.pack('!H', *(length * 4 + 20, )) + \
            pkt[4:10] + packedIP + pkt[20:length * 4]
        ipchecksum = checksum(dat)
        seq, = struct.unpack('!I', pkt[(length + 1) * 4:(length + 2) * 4])
        tcppkt = struct.pack('!H H I I H H H', *(srcport, dstport, 0, seq + 1, (5 << 12) + 21, 0, 0))
        tcpchksum = packedIP + struct.pack('!B B H', *(0, TCP, 20)) + tcppkt
        tcpchecksum = checksum(tcpchksum)
        tcp = struct.pack('!H H I I H H H H', *(srcport, dstport, 0, seq + 1, (5 << 12) + 21, 0, tcpchecksum, 0))
        response = pkt[:2] + struct.pack('!H', *(length * 4 + 20, )) + \
            pkt[4:10] + struct.pack('!H', *(ipchecksum,)) + packedIP + pkt[20:length * 4] + \
                tcp
        self.iface_int.send_ip_packet(response)

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        verdict = 'pass'

        matchrule = None
        for rule in self.rules:
            if rule.match(pkt, pkt_dir):
                matchrule = rule
                verdict = rule.verdict
                break

        #  drop case
        if verdict == 'drop':
            return

        if verdict == 'deny':
            rtype = matchrule.ruletype
            if rtype == 'dns':
                self._dnsDispatch(pkt, pkt_dir, matchrule.qcode)
            else:
                self._tcpForward(pkt, pkt_dir)
            return

        for rule in self.httprules:
            if rule.match(pkt, pkt_dir):
                break

        # pass case
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        else:
            self.iface_ext.send_ip_packet(pkt)


def makeDnsPkt(pkt, qcode):
    """
        makes DNS packet with question type
        of qcode
    """
    fmt = struct.Struct('!H')
    id = fmt.unpack(pkt[:2])
    pointer = 12
    domain, pointer = getString(pkt, pointer)
    response = makeResponseForA(domain, qcode, ipToInt(SERVER_IP))
    anspkt = makeResponseForA(domain, qcode, ipToInt(SERVER_IP))
    anspkt = fmt.pack(*id) + anspkt[2:]
    return anspkt

def requestMaker(domain, typeOf, answers= 0, isResponse = 0):
    ID = random.randint(0, (1 << 16) - 1)
    ID = (ID, 256 | (isResponse << 15))
    fmt = struct.Struct("!H H")
    ID = fmt.pack(*ID)
    data = ID
    data += b"\x00\x01"
    fmt = struct.Struct("!H")
    ans = (answers,)
    data += fmt.pack(*ans)
    data += b"\00\x00\x00\x00"
    domain = domain.split('.')
    fmt = struct.Struct("!B")
    for s in domain:
        l = (len(s),)
        data += fmt.pack(*l)
        data += s.encode()
    if domain[-1] != '':
        data += b"\x00"
    fmt = struct.Struct("!H H")
    typeAndClass = (typeOf, IN)
    typeAndClass = fmt.pack(*typeAndClass)
    data += typeAndClass
    return data

def writeString(data, domain):
    domain = domain.split('.')
    fmt = struct.Struct("!B")
    for s in domain:
        l = (len(s),)
        data += fmt.pack(*l)
        data += s.encode()
    if domain[-1] != '':
        data += b"\x00"
    return data

def makeResponseForA(domain, qtype, IP, ttl= 60):
    ttl = int(ttl)
    domain = domain
    typeOf = qtype
    fmt = struct.Struct('!I')
    IPData = fmt.pack(*(IP,))
    data = requestMaker(domain, qtype, 1, 1)
    data = writeString(data, domain)
    fmt = struct.Struct("!H H I H")
    qT = (typeOf, IN, ttl, 4)
    data += fmt.pack(*qT)
    data += IPData
    return data

class HTTPRule:
    def __init__(self, rule):
        rule = rule.split(' ')
        rule = filter(lambda elem: False if elem == '' else True, rule)
        self.verdict = rule[0]
        self.ruletype = rule[1]
        self.domain = rule[2]
        self.ip = None
        try:
            ip = ipToInt(rule[2])
            self.ip = ip
        except ValueError:
            self.ip = None
        self.httpCache = {}
        self.trakingFragments = {}


    def _checkHost(self, host, ip):
        if self.domain[0] == '*':
            if host.endswith(self.domain[1:]):
                return True
        elif self.domain[-1] == '*':
            if host.startswith(self.domain[:-1]):
                return True
        elif self.domain == host:
            return True
        
        return ip == self.ip

    def _headersGot(self, data, sockID):
        """
            checks if we already got all data to determine
            type of HTTP request and host also
        """
        if sockID not in self.trakingFragments:
            self.trakingFragments[sockID] = data
        else:
            self.trakingFragments[sockID] += data
        
        return '\r\n' in self.trakingFragments[sockID]

    def _getHeaders(self, sockID):
        pkt = self.trakingFragments[sockID]

        del self.trakingFragments[sockID]

        return pkt

    def match(self, pkt, pkt_dir):
        srcip, dstip, ptype, pkt = readIPPkt(pkt)
        if ptype != TCP:
            return False

        srcport, dstport = getPorts(pkt)

        if pkt_dir == PKT_DIR_INCOMING:
            temp = srcip
            srcip, dstip = dstip, temp
            temp1 = srcport
            srcport, dstport = dstport, temp1


        if dstport != 80:
            return False
        
        fmt = struct.Struct('!B')
        size, = fmt.unpack(pkt[12:13])
        size >>= 4
        http = pkt[size << 2:]

        sockID = (dstip, srcip, srcport, dstport)

        if pkt_dir == PKT_DIR_INCOMING and sockID not in self.httpCache:
            return True

        if not self._headersGot(http, sockID):
            return True

        http = self._getHeaders(sockID)

        http = http.split('\r\n\r\n')[0]

        if len(http) == 0:
            return False

        http = http.split('\r\n')
        headers = parseHeader(http[1:])
        typeAndPath = http[0]
        
        if 'host' in headers:
            host = headers['host']
            if self._checkHost(host, dstip):
                self.httpCache[(dstip, srcip, srcport, dstport)] = host + ' ' + typeAndPath
                return True
            else:
                return False
        elif pkt_dir == PKT_DIR_INCOMING:
            if (dstip, srcip, srcport, dstport) not in self.httpCache:
                return self._checkHost('---', dstip)
            prev = self.httpCache[(dstip, srcip, srcport, dstport)]

            # erase already used data
            del self.httpCache[(dstip, srcip, srcport, dstport)]

            statuscode = typeAndPath.split(' ')[1]
            length = '0'
            if 'content-length' in headers:
                length = headers['content-length']

            # data to log
            data = prev + ' ' + statuscode + ' ' + length + '\n'
            outFile.write(data)
            outFile.flush()
            return True

        return False

    def __str__(self):
        """
            string representation of Rule object
            @returns cache casted to string
        """
        ans = {}
        ans['type'] = self.ruletype
        ans['verdict'] = self.verdict
        ans['pattern'] = self.domain
        if self.ip:
            ans['ip'] = self.ip
        ans = str(ans)

        return ans


def parseHeader(data):
    dat = {}
    for line in data:
        pos = line.find(': ')
        name = line[:pos].lower()
        val = line[pos+2:]
        dat[name] = val

    return dat

def checksum(data):
    result = 0
    for i in range(0, len(data), 2):
        val, = struct.unpack('!H', data[i:i + 2])
        result += val
    if len(data) % 2 == 1:
        val, = struct.unpack('!B', data[len(data) - 1:])
        result += val
    while result >> 16:  # has more than 16 bits
        result = (result & 0xFFFF) + (result >> 16)
    return ~result & 0xFFFF  # want to flip only the rightmost 16 bits        

class Rule:
    def __init__(self, rule, ipDB):
        rule = rule.split(' ')
        rule = filter(lambda elem: False if elem == '' else True, rule)
        self.verdict = rule[0]
        self.ruletype = rule[1]
        self.countryCode = None
        if self.ruletype == 'dns':
            self.forDns(rule)
        else:
            self.forOthers(rule, ipDB)

    def forDns(self, rule):
        """
            reading pattern for DNS
        """
        pat = rule[2]
        if pat == 'any':
            pat = '*'
        if pat[-1] != '*':
            pat += '.'
        self.pattern = pat

    def getPort(self, port):
        """
            gets port range
        """
        l, r = 0, 0
        if '-' in port:
            port = port.split('-')
            l, r = int(port[0]), int(port[1])
        elif port == 'any':
            l, r = 0, 65535
            if self.ruletype == 'icmp':
                r = 255
        else:
            l = r = int(port)
        
        if self.ruletype == 'icmp':
            self.typeRange = (l, r)
        else:
            self.portRange = (l, r)

    def getIP(self, ip, ipDB):
        """
            gets ip range
        """
        l, r = 0, 0
        self.ipRanges = []
        if '/' in ip:
            pp = ip.split('/')
            ip, subnet = pp[0], pp[1]
            ip = ipToInt(ip)
            subnet = int(subnet)
            l = ip & (((1 << 32) - 1) - ((1 << (32 - subnet)) - 1))
            r = l + ((1 << (32 - subnet)) - 1)
            self.ipRanges.append((l, r))
        elif ip == 'any':
            l, r = 0, 4294967295
            self.ipRanges.append((l, r))
        elif '.' in ip:
            ip = ipToInt(ip)
            l, r = ip, ip
            self.ipRanges.append((l, r))
        else:
            self.countryCode = ip
            self.ipRanges = ipDB[ip]


    def forOthers(self, rule, ipDB):
        """
            storing ip ranges and port range 
            for icmp, tcp and udp rules
        """
        self.getPort(rule[3])
        self.getIP(rule[2], ipDB)

    def _checkForDns(self, pkt):
        """
            checks if dns type rule matches 
            for the packet 
        """
        pkt = pkt[8:]
        fmt =  struct.Struct('!B')
        qcode, = fmt.unpack(pkt[2:3])
        if (1 << 7) & qcode == (1 << 7):
            return False
        pointer = 12
        domain, pointer = getString(pkt, pointer)
        qType, pointer = getQType(pkt, pointer)
        self.qcode = qcode
        if qType == TYPE_A or qType == TYPE_AAAA:
            if self.pattern[0] == '*':
                return domain.endswith(self.pattern[1:])
            elif self.pattern[-1] == '*':
                return domain.startswith(self.pattern[:-1])
            else:
                return domain == self.pattern
        return False

    def _ipInRange(self, ip):
        """
            checks if ip is in ipRanges
        """
        ll, rr = 0, len(self.ipRanges) - 1
        ind = False
        while ll <= rr:
            mid = ll + rr >> 1
            l, r = self.ipRanges[mid]
            if ip >= l and ip <= r:
                return True
            if ip <= r:
                rr = mid - 1
            else:
                ll = mid + 1

        return False

    def match(self, pkt, pkt_dir):
        """
            checks if rule matches the packet
        """
        srcip, dstip, ptype, pkt = readIPPkt(pkt)

        if pkt_dir == PKT_DIR_INCOMING:
            temp = srcip
            srcip, dstip = dstip, temp

        if ptype == TCP:
            ptype = 'tcp'
        elif ptype == UDP:
            ptype = 'udp'
        elif ptype == ICMP:
            ptype = 'icmp'
        else:
            return False

        if self.ruletype == 'dns' and (ptype == 'tcp' or ptype == 'icmp'):
            return False

        if self.ruletype != 'dns' and ptype != self.ruletype:
            return False

        if ptype == 'icmp':
            fmt = struct.Struct('!B')
            tp, = fmt.unpack(pkt[:1])
            l, r = self.typeRange
            return self._ipInRange(dstip) and tp >= l and tp <= r

        srcport, dstport = getPorts(pkt)
        if pkt_dir == PKT_DIR_INCOMING:
            temp = srcport
            srcport, dstport = dstport, temp

        if self.ruletype == 'dns':
            if dstport != 53:
                return False
            return self._checkForDns(pkt)
        else:
            l, r = self.portRange
            if dstport >= l and dstport <= r and self._ipInRange(dstip):
                return True

        return False

    def __str__(self):
        """
            string representation of Rule object
            @returns cache casted to string
        """
        ans = {}
        ans['type'] = self.ruletype
        ans['verdict'] = self.verdict
        if self.countryCode != None:
            ans['country code'] = self.countryCode
        if self.ruletype == 'dns':
            ans['pattern'] = self.pattern
        else:
            ans['icmp types' if self.ruletype == 'icmp' else 'ports'] = self.typeRange if self.ruletype == 'icmp' else self.portRange
            ans['ip range numbers'] = len(self.ipRanges)
        ans = str(ans)

        return ans


def ipToInt(ip):
    """
        converts ip to 4 byte int
        @returns int ip in integer
    """
    ip = ip.split('.')
    ip = [int(elem) for elem in ip]
    ans = 0
    for elem in ip:
        ans <<= 8
        ans += elem

    return ans


def readRules(filename, ipDB):
    """
        reading rules from file with filename
        
        @returns list of rules
    """
    infile = open(filename, 'r')
    rulesData = []
    dat = infile.readlines()
    dat = filter(lambda elem: False if elem[0] == '%' or elem == '\n' \
                    or elem == '' or elem == None else True,\
                         dat)
    dat = map(lambda elem: elem[:-1].lower() if elem[-1] == '\n' else elem.lower(), dat)
    for rule in dat:
        newrule = None
        if rule[:3] == 'log':
            newrule = HTTPRule(rule)
        else:
            newrule = Rule(rule, ipDB)
        rulesData.append(newrule)

    return rulesData

def getPorts(pkt):
    """
        reads ports from tcp/udp header
    """
    fmt = struct.Struct('!H H')
    return fmt.unpack(pkt[:4])

def readIPPkt(pkt):
    """
        reads ip packet and returns source 
        and destination ip
    """
    fmt = struct.Struct('!B')
    length, = fmt.unpack(pkt[:1])
    length = length & ((1 << 4) - 1)
    ptype, = fmt.unpack(pkt[9:10])
    fmt = struct.Struct('!I I')
    srcip, dstip = fmt.unpack(pkt[12:20])
    pkt = pkt[(length << 2):]
    return srcip, dstip, ptype, pkt

def readIPDB():
    """
        reads ipdb file the name specified in constnats
        and returns dictionary from country code to IP lists
    """
    inFile = open(IP_DB_FILENAME, 'r')
    data = {}
    while True:
        s = inFile.readline()
        s = s[:-1]
        if s == '':
            break
        lst = s.split(' ')
        lst[-1] = lst[-1].lower()
        if lst[-1] not in data:
            data[lst[-1]] = []
        data[lst[-1]].append((ipToInt(lst[0]), ipToInt(lst[1])))
    
    return data

def getQType(data, pointer):
    """
        gets type of query
    """
    fmt = struct.Struct('!B B')
    i, j = fmt.unpack(data[pointer:pointer + 2])
    qType = (int(i) << 8) + int(j)
    return qType, pointer + 2

def getString(data, pointer):
    """
        this is method for reading Name, QName and RData
        in 'data' from 'pointer'
    """
    ansName = ""
    fmt = struct.Struct('!B')
    while True:
        size, = fmt.unpack(data[pointer:pointer + 1])
        size = int(size)
        pointer += 1
        if size & (3 << 6) == (3 << 6):
            size <<= 8
            pl, = fmt.unpack(data[pointer:pointer + 1])
            size += int(pl)
            pointer += 1
            newString, p = getString(data, size ^ (3 << 14))
            ansName += newString
            break
        elif size == 0:
            break
        ansName += data[pointer:pointer + size].decode() + "."
        pointer += size
    if ansName == "":
        ansName = "."
    return ansName, pointer