import struct
import socket
import base64
import gzip
import urllib.parse

class PacketHeader:
    header_format = '=IIII'
    size = struct.calcsize(header_format)

    def __init__(self, b):
        self.raw = b
        self.timestamp_second, self.tm, self.om, self.packet_length = struct.unpack(PacketHeader.header_format, b)

    def __str__(self):
        return str(struct.unpack(PacketHeader.header_format, self.raw))

class Ipv4Header:
    header_format = '>BBHHHBBHII'
    size = struct.calcsize(header_format)

    def __init__(self, b):
        self.raw = b
        self.vhl, self.st, self.total_length, self.i, self.ffo, self.t2l, self.protocol, self.checksum, self.src_addr, self.dest_addr = struct.unpack(Ipv4Header.header_format, b)
        self.src_addr = socket.inet_ntop(socket.AF_INET, struct.pack(">I", self.src_addr))
        self.dest_addr = socket.inet_ntop(socket.AF_INET, struct.pack(">I", self.dest_addr))

    def __str__(self):
        return str(struct.unpack(Ipv4Header.header_format, self.raw))

class TcpHeader:
    header_format = '>HHIIHHHH'
    size = struct.calcsize(header_format)
    
    def __init__(self, b):
        self.raw = b
        self.src_port, self.dest_port, self.seq, self.ack, self.hlf, self.ws, self.checksum, self.up = struct.unpack(TcpHeader.header_format, b)
    
    def __str__(self):
        return str(struct.unpack(TcpHeader.header_format, self.raw))

class TcpData:
    # https://imququ.com/post/transfer-encoding-header-in-http.html
    # https://www.runoob.com/http/http-messages.html
    def __init__(self, b):
        self.raw = b

        idx1 = b.find(b'\r\n')
        idx2 = b.find(b'\r\n\r\n')
        if idx1 != -1 and idx2 != -1:
            self.info = self.decode(b[:idx1])
            self.header = self.decode(b[idx1+2 : idx2])
            self.body = self.decode(b[idx2+4:])

            if self.body.find("data_list=") != -1:
                self.extra = gzip.decompress(base64.b64decode(urllib.parse.unquote(self.body[self.body.find("data_list=") + 10:]))).decode('utf-8')
            else:
                self.extra = "解析异常"
        else:
            self.info = "解析异常"
            self.header = "解析异常"
            self.body = "解析异常"
            self.extra = "解析异常"
        

    def __str__(self):
        return "%s\n%s\n\n%s" % (self.info, self.header, self.body)
    
    def decode(self, b):
        try:
            return b.decode('utf-8')
        except UnicodeDecodeError as e1:
            try:
                return b.decode('ascii')
            except UnicodeDecodeError as e2:
                result = ''
                for byte in b:
                    if 0x20 <= byte <= 0x7E:
                        result += chr(byte)
                    else:
                        result += '.'
                return result

class Packet:
    headers_size = PacketHeader.size + Ipv4Header.size + TcpHeader.size
    def __init__(self, b, f, count):
        self.frame = count
        self.packet_header = PacketHeader(b[0: PacketHeader.size])
        self.ipv4_header = Ipv4Header(b[PacketHeader.size: PacketHeader.size+Ipv4Header.size])
        self.tcp_header = TcpHeader(b[PacketHeader.size+Ipv4Header.size: ])
        self.tcp_data = TcpData(f.read(self.ipv4_header.total_length - 40))

    def __str__(self):
        return "Frame: %d\nPacket Header: %s\nIPV4 Header: %s\nTCP Header: %s\nData: %s\n" % (self.frame, self.packet_header, self.ipv4_header, self.tcp_header, self.tcp_data)

class PacpHeader:
    header_format = '=IHHiIII'
    size = struct.calcsize(header_format)
    def __init__(self, b):
        self.raw = b

    def __str__(self):
        return str(struct.unpack(PacpHeader.header_format, self.raw))


count = 0
def nextPacket(f):
    global count
    # 去 Pacp 的文件头
    if f.tell() < PacpHeader.size:
        f.seek(0)
        PacpHeader(f.read(PacpHeader.size))

    headers_byte = f.read(Packet.headers_size)
    if headers_byte != b'':
        count += 1
        return Packet(headers_byte, f, count)
    else:
        return None