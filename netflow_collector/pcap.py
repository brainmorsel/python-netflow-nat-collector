from __future__ import unicode_literals, print_function, division

# read and parse pcap file
# see http://wiki.wireshark.org/Development/LibpcapFileFormat
import struct

__author__ = 'dongliu'


class NoDataInInputBuffer(Exception):
    pass


class UnsupportFileFormat(Exception):
    pass


def get_parser(infile):
    head = infile.read(4)

    if len(head) < 4:
        raise NoDataInInputBuffer()

    magic_num, = struct.unpack(b'<I', head)
    if magic_num == 0xA1B2C3D4 or magic_num == 0x4D3C2B1A:
        return PcapFile(infile, head)
    else:
        raise UnsupportFileFormat()


class PcapFile(object):
    def __init__(self, infile, head):
        self.infile = infile
        self.byteorder = b'@'
        self.link_type = None

        self.pcap_check(head)

    # http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
    def pcap_check(self, head):
        """check the header of cap file, see it is a ledge pcap file.."""

        # default, auto
        # read 24 bytes header
        pcap_file_header_len = 24
        global_head = head + self.infile.read(pcap_file_header_len - len(head))

        if not global_head:
            raise UnsupportFileFormat()

        magic_num, = struct.unpack(b'<I', global_head[0:4])
        # judge the endian of file.
        if magic_num == 0xA1B2C3D4:
            self.byteorder = b'<'
        elif magic_num == 0x4D3C2B1A:
            self.byteorder = b'>'
        else:
            raise UnsupportFileFormat()

        self.version_major, self.version_minor, self.timezone, self.timestamp, self.max_package_len, self.link_type \
            = struct.unpack(self.byteorder + b'4xHHIIII', global_head)

    def read_pcap_pac(self):
        """
        read pcap header.
        return the total package length.
        """
        # package header
        pcap_header_len = 16
        package_header = self.infile.read(pcap_header_len)

        # end of file.
        if not package_header:
            return None, None

        seconds, suseconds, packet_len, raw_len = struct.unpack(self.byteorder + b'IIII',
                                                                package_header)
        micro_second = seconds * 1000000 + suseconds
        # note: packet_len contains padding.
        link_packet = self.infile.read(packet_len)
        if len(link_packet) < packet_len:
            return None, None
        return micro_second, link_packet

    def read_packet(self):
        while True:
            micro_second, link_packet = self.read_pcap_pac()
            if link_packet:
                yield self.link_type, micro_second, link_packet
            else:
                return
