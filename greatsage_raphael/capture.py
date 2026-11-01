"""Reads Ethernet PCAP and PCAPNG captures with bounded resource use."""
from dataclasses import dataclass, field
import struct
import hashlib
import ipaddress
import os
import stat

MAX_FILE = 256 * 1024 * 1024
MAX_RECORD = 1024 * 1024
MAX_PACKETS = 200_000
MAX_INTERFACES = 256
MAX_BLOCKS = 1_000_000

class CaptureError(ValueError):
    pass

@dataclass
class Packet:
    number: int
    time: float
    source: str = ''
    destination: str = ''
    protocol: str = 'Ethernet'
    sport: int = 0
    dport: int = 0
    info: dict = field(default_factory=dict)


def exact(f, size):
    if size<0 or size>MAX_RECORD or f.tell()+size>MAX_FILE:
        raise CaptureError('Capture read exceeds a safety limit.')
    data = f.read(size)
    if len(data) != size:
        raise CaptureError('Truncated capture: a declared record is incomplete.')
    return data


def records(f, cancel=None):
    magic = exact(f, 4)
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1e6), b'\xa1\xb2\xc3\xd4': ('>', 1e6),
               b'\x4d\x3c\xb2\xa1': ('<', 1e9), b'\xa1\xb2\x3c\x4d': ('>', 1e9)}
    if magic in formats:
        endian, scale = formats[magic]
        major, minor, _, _, snap, link = struct.unpack(endian + 'HHIIII', exact(f, 20))
        if (major, minor) != (2, 4) or link != 1:
            raise CaptureError('Only PCAP 2.4 Ethernet captures are supported.')
        while header := f.read(16):
            if cancel is not None and cancel.is_set():raise CaptureError('Analysis cancelled.')
            if len(header) != 16:
                raise CaptureError('Truncated PCAP record header.')
            sec, fraction, size, original = struct.unpack(endian + 'IIII', header)
            if fraction >= scale:
                raise CaptureError('Invalid PCAP timestamp fraction.')
            if size > MAX_RECORD or size > snap or size > original:
                raise CaptureError('Invalid or oversized PCAP packet length.')
            yield sec + fraction / scale, exact(f, size)
        return
    if magic != b'\x0a\x0d\x0d\x0a':
        raise CaptureError('Expected a PCAP or PCAPNG capture.')
    f.seek(0)
    endian = None
    interfaces = []
    blocks=0
    while prefix := f.read(8):
        blocks+=1
        if blocks>MAX_BLOCKS:raise CaptureError('PCAPNG block-count safety limit exceeded.')
        if cancel is not None and cancel.is_set():raise CaptureError('Analysis cancelled.')
        if len(prefix) != 8:
            raise CaptureError('Truncated PCAPNG block.')
        if prefix[:4] == b'\x0a\x0d\x0d\x0a':
            bom = exact(f, 4)
            if bom not in (b'\x4d\x3c\x2b\x1a', b'\x1a\x2b\x3c\x4d'):
                raise CaptureError('Invalid PCAPNG byte order.')
            endian = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>'
            size = struct.unpack(endian + 'I', prefix[4:])[0]
            if size < 28 or size > MAX_RECORD or size % 4:
                raise CaptureError('Invalid PCAPNG section length.')
            body = bom + exact(f, size - 12)
            if struct.unpack(endian + 'HH', body[4:8]) != (1, 0):
                raise CaptureError('Only PCAPNG version 1.0 is supported.')
            interfaces = []
        else:
            if endian is None:
                raise CaptureError('Missing PCAPNG section.')
            size = struct.unpack(endian + 'I', prefix[4:])[0]
            if size < 12 or size > MAX_RECORD or size % 4:
                raise CaptureError('Invalid PCAPNG block length.')
            body = exact(f, size - 8)
        if struct.unpack(endian + 'I', body[-4:])[0] != size:
            raise CaptureError('PCAPNG block length mismatch.')
        kind = struct.unpack(endian + 'I', prefix[:4])[0]
        payload = body[:-4]
        if kind == 1:
            if len(interfaces)>=MAX_INTERFACES:raise CaptureError('PCAPNG interface-count safety limit exceeded.')
            if len(payload) < 8:
                raise CaptureError('Truncated PCAPNG interface.')
            link, _, snap = struct.unpack(endian + 'HHI', payload[:8])
            resolution = 1e-6
            time_offset = 0
            offset = 8
            options=0
            while offset + 4 <= len(payload):
                options+=1
                if options>1024:raise CaptureError('PCAPNG interface-option safety limit exceeded.')
                code, length = struct.unpack(endian + 'HH', payload[offset:offset+4]); offset += 4
                if offset + length > len(payload):
                    raise CaptureError('Truncated interface option.')
                if code == 9 and length == 1:
                    value = payload[offset]
                    resolution = (2 if value & 128 else 10) ** -(value & 127)
                if code == 14 and length == 8:
                    time_offset = struct.unpack(endian + 'q', payload[offset:offset+8])[0]
                offset += (length + 3) & ~3
                if code == 0:
                    break
            interfaces.append((link, snap, resolution, time_offset))
        elif kind == 6:
            if len(payload) < 20:
                raise CaptureError('Truncated PCAPNG packet.')
            interface, high, low, cap, original = struct.unpack(endian + 'IIIII', payload[:20])
            if interface >= len(interfaces):
                raise CaptureError('Unknown PCAPNG interface.')
            link, snap, resolution, time_offset = interfaces[interface]
            if link != 1:
                raise CaptureError('Only Ethernet PCAPNG interfaces are supported.')
            if cap > MAX_RECORD or cap > original or (snap and cap > snap) or 20 + ((cap+3)&~3) > len(payload):
                raise CaptureError('Invalid PCAPNG packet length.')
            yield ((high << 32) | low) * resolution + time_offset, payload[20:20+cap]
        elif kind in (2, 3):
            raise CaptureError('Legacy/simple PCAPNG packet blocks are unsupported; export enhanced packet blocks.')


def ip(data):
    return '.'.join(str(x) for x in data)


def decode(number, timestamp, data):
    p = Packet(number, timestamp)
    if len(data) < 14:
        raise ValueError('Short Ethernet frame')
    kind = int.from_bytes(data[12:14], 'big'); offset = 14
    for _ in range(2):
        if kind in (0x8100, 0x88a8):
            if len(data) < offset + 4: raise ValueError('Short VLAN frame')
            kind = int.from_bytes(data[offset+2:offset+4], 'big'); offset += 4
    payload = data[offset:]
    if kind == 0x0806:
        if len(payload) < 28: raise ValueError('Short ARP frame')
        if payload[:6] != b'\x00\x01\x08\x00\x06\x04': return p
        p.protocol = 'ARP'; p.source = ip(payload[14:18]); p.destination = ip(payload[24:28])
        p.info = {'mac': payload[8:14].hex(':'), 'op': int.from_bytes(payload[6:8], 'big')}
    elif kind == 0x0800:
        if len(payload) < 20 or payload[0] >> 4 != 4: raise ValueError('Short IPv4 header')
        ihl = (payload[0] & 15) * 4; total = int.from_bytes(payload[2:4], 'big')
        if ihl < 20 or ihl > len(payload) or total < ihl: raise ValueError('Invalid IPv4 length')
        p.source, p.destination = ip(payload[12:16]), ip(payload[16:20]); p.protocol = 'IPv4'
        if total > len(payload): raise ValueError('Truncated IPv4 packet')
        if int.from_bytes(payload[6:8], 'big') & 0x3fff:
            p.info['fragment'] = True
            return p
        if total > len(payload): raise ValueError('Truncated IPv4 packet')
        segment = payload[ihl:total]
        proto = payload[9]
        decode_transport(p, segment, proto)
    elif kind == 0x86dd:
        if len(payload) < 40 or payload[0] >> 4 != 6:raise ValueError('Short IPv6 header')
        length=int.from_bytes(payload[4:6],'big')
        if length==0:raise ValueError('IPv6 jumbograms are unsupported')
        if len(payload)<40+length:raise ValueError('Truncated IPv6 packet')
        p.source=str(ipaddress.IPv6Address(payload[8:24]));p.destination=str(ipaddress.IPv6Address(payload[24:40]))
        p.protocol='IPv6';proto=payload[6];offset=40;end=40+length
        for _ in range(16):
            if proto==44:
                if offset+8>end:raise ValueError('Short IPv6 fragment header')
                p.info['fragment']=True;return p
            if proto not in (0,43,60,51):break
            if offset+2>end:raise ValueError('Short IPv6 extension header')
            size=(payload[offset+1]+(2 if proto==51 else 1))*(4 if proto==51 else 8)
            if offset+size>end:raise ValueError('Truncated IPv6 extension header')
            proto=payload[offset];offset+=size
        else:raise ValueError('IPv6 extension limit exceeded')
        decode_transport(p,payload[offset:end],proto)
    return p


def quoted_packet(data):
    """Returns endpoint fields from the packet header quoted in an ICMP error."""
    if not data:return {}
    version=data[0]>>4
    if version==4 and len(data)>=20:
        offset=(data[0]&15)*4
        if offset<20 or offset>len(data):return {}
        result={'source':ip(data[12:16]),'destination':ip(data[16:20]),'ip_protocol':data[9]}
    elif version==6 and len(data)>=40:
        offset=40
        result={'source':str(ipaddress.IPv6Address(data[8:24])),'destination':str(ipaddress.IPv6Address(data[24:40])),'ip_protocol':data[6]}
    else:return {}
    if result['ip_protocol'] in (6,17) and offset+4<=len(data):
        result['source_port'],result['destination_port']=struct.unpack('!HH',data[offset:offset+4])
    return result


def decode_transport(p, segment, proto):
    if proto == 6:
        if len(segment) < 20: raise ValueError('Short TCP header')
        p.protocol = 'TCP'; p.sport, p.dport, seq, ack = struct.unpack('!HHII', segment[:12])
        hlen = (segment[12] >> 4) * 4
        if hlen < 20 or hlen > len(segment): raise ValueError('Invalid TCP header length')
        p.info = {'seq': seq, 'ack': ack, 'flags': segment[13], 'length': len(segment)-hlen,
                  'payload_hash': hashlib.blake2s(segment[hlen:], digest_size=16).hexdigest()}
    elif proto == 17:
        if len(segment) < 8: raise ValueError('Short UDP header')
        p.protocol = 'UDP'; p.sport, p.dport, length, _ = struct.unpack('!HHHH', segment[:8])
        if length < 8 or length > len(segment): raise ValueError('Invalid UDP length')
        body = segment[8:length]
        if 53 in (p.sport, p.dport):
            if len(body)<12:raise ValueError('Short DNS header')
            p.protocol = 'DNS'
            ident, flags = struct.unpack('!HH', body[:4])
            p.info = {'id': ident, 'response': bool(flags & 0x8000), 'rcode': flags & 15,
                      **decode_dns(body)}
        elif ':' not in p.source and {p.sport, p.dport} == {67, 68} and len(body) >= 240 and body[236:240] == b'\x63\x82\x53\x63':
            p.protocol = 'DHCP'; p.info = {'op': body[0], 'transaction': body[4:8].hex()}
            option = 240
            while option < len(body):
                code = body[option]; option += 1
                if code == 255: break
                if code == 0: continue
                if option >= len(body): raise ValueError('Short DHCP option')
                size = body[option]; option += 1
                if option + size > len(body): raise ValueError('Short DHCP option data')
                if code == 54 and size == 4: p.info['server'] = ip(body[option:option+4])
                if code == 53 and size == 1: p.info['message_type'] = body[option]
                option += size
    elif proto in (1,58):
        p.protocol = 'ICMP' if proto==1 else 'ICMPv6'
        if len(segment) < 8: raise ValueError('Short ICMP header')
        p.info = {'type': segment[0], 'code': segment[1]}
        if (proto==1 and segment[0]==3 and segment[1]==4) or (proto==58 and segment[0]==2):
            p.info['mtu']=int.from_bytes(segment[4:8] if proto==58 else segment[6:8], 'big')
        if (proto==1 and segment[0] in (3,11)) or (proto==58 and segment[0] in (1,2,3)):
            p.info['quoted'] = quoted_packet(segment[8:])


def decode_dns(body):
    """Parses bounded DNS questions and address answers, including compressed names."""
    if len(body)<12:raise ValueError('Short DNS header')
    def name_at(start):
        labels = []; seen = set(); pos = start; end = None; wire_length=1
        for _ in range(128):
            if pos >= len(body) or pos in seen: raise ValueError('Invalid DNS name')
            seen.add(pos); size = body[pos]; pos += 1
            if size == 0: return '.'.join(labels).lower(), end or pos
            if size & 0xc0 == 0xc0:
                if pos >= len(body): raise ValueError('Short DNS pointer')
                pointer = ((size & 63) << 8) | body[pos]
                if end is None: end = pos + 1
                pos = pointer; continue
            if size & 0xc0 or pos + size > len(body): raise ValueError('Invalid DNS label')
            wire_length+=size+1
            if wire_length>255:raise ValueError('DNS name exceeds 255 bytes')
            label=''.join(chr(value) if 48<=value<=57 or 65<=value<=90 or 97<=value<=122 or value in (45,95) else '\\'+str(value).zfill(3) for value in body[pos:pos+size])
            labels.append(label); pos += size
        raise ValueError('DNS compression limit exceeded')
    qd, an = struct.unpack('!HH', body[4:8])
    if qd > 64 or an > 1024: raise ValueError('DNS count limit exceeded')
    questions = []; answers = []; offset = 12
    for _ in range(qd):
        name, offset = name_at(offset)
        if offset + 4 > len(body): raise ValueError('Short DNS question')
        typ, cls = struct.unpack('!HH', body[offset:offset+4]); offset += 4
        questions.append([name, typ, cls])
    for _ in range(an):
        name, offset = name_at(offset)
        if offset + 10 > len(body): raise ValueError('Short DNS answer')
        typ, cls, ttl, size = struct.unpack('!HHIH', body[offset:offset+10]); offset += 10
        if offset + size > len(body): raise ValueError('Short DNS answer data')
        if cls == 1 and ((typ == 1 and size == 4) or (typ == 28 and size == 16)):
            answers.append([name, str(ipaddress.ip_address(body[offset:offset+size]))])
        offset += size
    return {'questions': questions, 'answers': answers, 'truncated': bool(body[2] & 2)}


def read_capture(path, cancel=None):
    packets, warnings = [], []
    skipped=0
    latest=None
    clock_warning=False
    descriptor=os.open(path,os.O_RDONLY | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise CaptureError('Choose a regular capture file, not a device, directory or pipe.')
    with os.fdopen(descriptor, 'rb') as f:
        f.seek(0, 2)
        if f.tell() > MAX_FILE:
            raise CaptureError('Capture exceeds the 256 MiB safety limit. Split it into smaller files.')
        f.seek(0)
        for number, (timestamp, data) in enumerate(records(f,cancel), 1):
            if cancel is not None and cancel.is_set():
                raise CaptureError('Analysis cancelled.')
            if number > MAX_PACKETS:
                warnings.append('Analysis stopped at 200,000 packets; findings cover only this prefix.')
                break
            if latest is not None and timestamp<latest and not clock_warning:
                warnings.append('Capture timestamps are out of order; timing-based findings may be incomplete or unreliable.');clock_warning=True
            latest=timestamp
            try:
                packets.append(decode(number, timestamp, data))
            except (ValueError, IndexError, struct.error):
                skipped+=1
                if len(warnings) < 50: warnings.append(f'Packet {number}: malformed or truncated protocol data; skipped.')
    if skipped:warnings.append(f'{skipped} malformed or truncated packet(s) skipped; diagnoses cover decoded packets only.')
    return packets, warnings
