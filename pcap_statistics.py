import pyshark
import sys
from collections import namedtuple
import numpy as np

if len(sys.argv) < 2:
    print 'pcap file is required'
    sys.exit(0)

file = sys.argv[1]
print file

cap = pyshark.FileCapture(file, display_filter='smpp')

Message = namedtuple("Message", ["ip_src", "srcport", "ip_dst", "dstport", "sequence_number"])
d = {}
for packet in cap:

    for smpp in packet.get_multiple_layers('smpp'):
        if smpp.command_id == '0x00000004':
            msgKey = Message(ip_src=packet.ip.src, srcport=packet.tcp.srcport, ip_dst=packet.ip.dst,
                             dstport=packet.tcp.dstport, sequence_number=smpp.sequence_number)
        elif smpp.command_id == '0x80000004':
            msgKey = Message(ip_dst=packet.ip.src, dstport=packet.tcp.srcport, ip_src=packet.ip.dst,
                             srcport=packet.tcp.dstport, sequence_number=smpp.sequence_number)
        else:
            continue

        if msgKey in d:
            d[msgKey].append(packet.sniff_time)
        else:
            d[msgKey] = [packet.sniff_time]

l = []
print 'ip_src,srcport, ip_dst,dstport,sequence_number,response_time'
for key, value in d.iteritems():
    if len(value) > 1:
        response_time = (value[1] - value[0]).total_seconds()
        print '%s,%f' % (','.join(list(key)), response_time)
        l.append(response_time)


a = np.array(l)
p = np.percentile(a, 99)
print '99 percentile: %f' % (p)
print 'max response_time: %f' % (a.max())
