import collections
from . import util


PacketHeader = util.structuple('NfHeader', '!HHIIII', 'version count sysUpTime unixSecs seqNumber srcId')
FlowSetHeader = util.structuple('NfFlowSetHeader', '!HH', 'flowSetId length')
FlowSetTplHeader = util.structuple('NfFlowSetTplHeader', '!HH', 'templateId fieldCount')
FlowSetTplRecord = util.structuple('NfFlowSetTplRecord', '!HH', 'fieldType fieldLength')


def u_int(length):
    if length == 1:
        return 'B'
    elif length == 2:
        return 'H'
    elif length == 4:
        return 'L'
    elif length == 8:
        return 'Q'
    else:
        return byte_a(length)


def byte_a(length):
    return '{0}B'.format(length)


class FieldTypeTable:
    def __init__(self):
        table = [
            # Value, Length, Format, Field Type
            (1,  4,  u_int, 'IN_BYTES'),
            (2,  4,  u_int, 'IN_PKTS'),
            (3,  4,  u_int, 'FLOWS'),
            (4,  1,  u_int, 'PROTOCOL'),
            (5,  1,  u_int, 'TOS'),
            (6,  1,  u_int, 'TCP_FLAGS'),
            (7,  2,  u_int, 'L4_SRC_PORT'),
            (8,  4,  u_int, 'IPV4_SRC_ADDR'),
            (9,  1,  u_int, 'SRC_MASK'),
            (10, 2,  u_int, 'INPUT_SNMP'),
            (11, 2,  u_int, 'L4_DST_PORT'),
            (12, 4,  u_int, 'IPV4_DST_ADDR'),
            (13, 1,  u_int, 'DST_MASK'),
            (14, 2,  u_int, 'OUTPUT_SNMP'),
            (15, 4,  u_int, 'IPV4_NEXT_HOP'),
            (16, 2,  u_int, 'SRC_AS'),
            (17, 2,  u_int, 'DST_AS'),
            (18, 4,  u_int, 'BGP_IPV4_NEXT_HOP'),
            (19, 4,  u_int, 'MUL_DST_PKTS'),
            (20, 4,  u_int, 'MUL_DST_BYTES'),
            (21, 4,  u_int, 'LAST_SWITCHED'),
            (22, 4,  u_int, 'FIRST_SWITCHED'),
            (23, 4,  u_int, 'OUT_BYTES'),
            (24, 4,  u_int, 'OUT_PKTS'),
            (27, 16, u_int, 'IPV6_SRC_ADDR'),
            (28, 16, u_int, 'IPV6_DST_ADDR'),
            (29, 1,  u_int, 'IPV6_SRC_MASK'),
            (30, 1,  u_int, 'IPV6_DST_MASK'),
            (31, 3,  u_int, 'IPV6_FLOW_LABEL'),
            (32, 2,  u_int, 'ICMP_TYPE'),
            (33, 1,  u_int, 'MUL_IGMP_TYPE'),
            (34, 4,  u_int, 'SAMPLING_INTERVAL'),
            (35, 1,  u_int, 'SAMPLING_ALGORITHM'),
            (36, 2,  u_int, 'FLOW_ACTIVE_TIMEOUT'),
            (37, 2,  u_int, 'FLOW_INACTIVE_TIMEOUT'),
            (38, 1,  u_int, 'ENGINE_TYPE'),
            (39, 1,  u_int, 'ENGINE_ID'),
            (40, 4,  u_int, 'TOTAL_BYTES_EXP'),
            (41, 4,  u_int, 'TOTAL_PKTS_EXP'),
            (42, 4,  u_int, 'TOTAL_FLOWS_EXP'),
            (46, 1,  u_int, 'MPLS_TOP_LABEL_TYPE'),
            (47, 4,  u_int, 'MPLS_TOP_LABEL_IP_ADDR'),
            (48, 1,  u_int, 'FLOW_SAMPLER_ID'),
            (49, 1,  u_int, 'FLOW_SAMPLER_MODE'),
            (50, 4,  u_int, 'FLOW_SAMPLER_RANDOM_INTERVAL'),
            (55, 1,  u_int, 'DST_TOS'),
            (56, 6,  u_int, 'SRC_MAC'),
            (57, 6,  u_int, 'DST_MAC'),
            (58, 2,  u_int, 'SRC_VLAN'),
            (59, 2,  u_int, 'DST_VLAN'),
            (60, 1,  u_int, 'IP_PROTOCOL_VERSION'),
            (61, 1,  u_int, 'DIRECTION'),
            (62, 16, u_int, 'IPV6_NEXT_HOP'),
            (63, 16, u_int, 'BGP_IPV6_NEXT_HOP'),
            (64, 4,  u_int, 'IPV6_OPTION_HEADERS'),
            (70, 3,  u_int, 'MPLS_LABEL_1'),
            (71, 3,  u_int, 'MPLS_LABEL_2'),
            (72, 3,  u_int, 'MPLS_LABEL_3'),
            (73, 3,  u_int, 'MPLS_LABEL_4'),
            (74, 3,  u_int, 'MPLS_LABEL_5'),
            (75, 3,  u_int, 'MPLS_LABEL_6'),
            (76, 3,  u_int, 'MPLS_LABEL_7'),
            (77, 3,  u_int, 'MPLS_LABEL_8'),
            (78, 3,  u_int, 'MPLS_LABEL_9'),
            (79, 3,  u_int, 'MPLS_LABEL_10'),
            (80, 6,  u_int, 'IN_DST_MAC'),
            (81, 6,  u_int, 'OUT_SRC_MAC'),
            (82, 0,  byte_a, 'IF_NAME'),
            (83, 0,  byte_a, 'IF_DESC'),
            (84, 0,  byte_a, 'SAMPLER_NAME'),
            (85, 0,  u_int, 'IN_PERMANENT_BYTES'),
            (86, 0,  u_int, 'IN_PERMANENT_PKTS'),
            (89, 1,  u_int, 'FORWARDING_STATUS'),
            (128, 4, u_int, 'BGP_ADJ_NEXT_AS'),
            (129, 4, u_int, 'BGP_ADJ_PREV_AS'),
            # Cisco NSEL
            (148, 4, u_int, 'CONN_ID'),
            (176, 1, u_int, 'ICMP_TYPE'),
            (177, 1, u_int, 'ICMP_CODE'),
            (178, 1, u_int, 'ICMP_TYPE_IPV6'),
            (179, 1, u_int, 'ICMP_CODE_IPV6'),
            (225, 4, u_int, 'XLATE_SRC_ADDR_IPV4'),
            (226, 4, u_int, 'XLATE_DST_ADDR_IPV4'),
            (227, 2, u_int, 'XLATE_SRC_PORT'),
            (228, 2, u_int, 'XLATE_DST_PORT'),
            (281, 16, u_int, 'XLATE_SRC_ADDR_IPV6'),
            (282, 16, u_int, 'XLATE_DST_ADDR_IPV6'),
            (233, 1, u_int, 'FW_EVENT'),  # 0:ignore 1:created 2:deleted 3:denied 4:alert 5:update
            (33002, 2, u_int, 'FW_EXT_EVENT'),  # 0:ignore >1000:denied 1001:ingress ACL 1002:egress ACL 1003:connect or ICMP 1004:not TCP SYN >2000:deleted
            (323, 8, u_int, 'EVENT_TIME_MSEC'),  # milliseconds
            (324, 8, u_int, 'EVENT_TIME_USEC'),  # microseconds
            (325, 8, u_int, 'EVENT_TIME_NSEC'),  # nanoseconds
            (152, 8, u_int, 'FLOW_CREATE_TIME_MSEC'),
            (231, 4, u_int, 'FWD_FLOW_DELTA_BYTES'),
            (232, 4, u_int, 'REV_FLOW_DELTA_BYTES'),
            (33000, 12, byte_a, 'INGRESS_ACL_ID'),
            (33001, 12, byte_a, 'EGRESS_ACL_ID'),
            (40000, 0, byte_a, 'USERNAME'),  # len: 20 or 65
            # Cisco ASR 1000 series NEL extension - Nat Event Logging
            (230, 1, u_int, 'NAT_EVENT'),
            (234, 4, u_int, 'INGRESS_VRFID'),
            (235, 4, u_int, 'EGRESS_VRFID'),
            (361, 2, u_int, 'XLATE_PORT_BLOCK_START'),
            (362, 2, u_int, 'XLATE_PORT_BLOCK_END'),
            (363, 2, u_int, 'XLATE_PORT_BLOCK_STEP'),
            (364, 2, u_int, 'XLATE_PORT_BLOCK_SIZE'),
        ]
        self._lookup_id = {}
        self._lookup_name = {}

        for item in table:
            self._lookup_id[item[0]] = item
            self._lookup_name[item[3]] = item

    def get(self, fieldType):
        return self._lookup_id.get(fieldType, (fieldType, 0, u_int, 'FIELD_{0}'.format(fieldType)))

    def get_by_name(self, name):
        return self._lookup_name.get(name)


class TemplateMatcher:
    FIELDS = FieldTypeTable()

    def __init__(self):
        self._dyn_templates = collections.defaultdict(dict)
        self._static_templates = {}

    def update_teplate(self, addr, template_id, records):
        fmt_list = ['!']
        names = []
        for record in records:
            fieldType, _, fmtr, name = self.FIELDS.get(record.fieldType)
            names.append(name)
            fmt_list.append(fmtr(record.fieldLength))

        nf_template = util.structuple('Template_{0}'.format(template_id), ''.join(fmt_list), names)
        self._dyn_templates[addr][template_id] = nf_template

    def add_static_template(self, field_names):
        fmt_list = ['!']
        for name in field_names:
            field_len = 0
            try:
                name, field_len = name.split(':')
            except ValueError:
                pass
            fieldType, default_len, fmtr, _ = self.FIELDS.get_by_name(name)
            field_len = field_len or default_len
            fmt_list.append(fmtr(field_len))
        template = util.structuple('Template_dynamic', ''.join(fmt_list), field_names)
        self._static_templates[template.size + FlowSetHeader.size] = template
        # print('template: %d %s' % (template.size + FlowSetHeader.size, template.format))

    def match(self, addr, template_id):
        if addr in self._dyn_templates and template_id in self._dyn_templates[addr]:
            return self._dyn_templates[addr][template_id]
        return None


class Parser:
    def __init__(self, version):
        self.version = version
        self._tpl_matcher = TemplateMatcher()
        self._lastSeqId = 0

    def add_template(self, *field_names):
        self._tpl_matcher.add_static_template(field_names)

    def parse(self, buffer, addr):
        offset = 0
        pkt_len = len(buffer)
        pkt_header = PacketHeader(buffer, offset)
        offset += PacketHeader.size

        if pkt_header.version != self.version:
            # show warning and exit
            return

        while offset < pkt_len:
            fs_header = FlowSetHeader(buffer, offset)
            fs_offset = offset + FlowSetHeader.size
            offset += fs_header.length

            # if self._lastSeqId and pkt_header.seqNumber - self._lastSeqId > 1:
            #     print('!!! LOST PACKETS: %d' % (pkt_header.seqNumber - self._lastSeqId - 1))
            # self._lastSeqId = pkt_header.seqNumber

            if fs_header.flowSetId == 0:
                while fs_offset < offset:
                    fs_tpl_header = FlowSetTplHeader(buffer, fs_offset)
                    fs_offset += FlowSetTplHeader.size

                    tpl_records = []
                    for _ in range(fs_tpl_header.fieldCount):
                        record = FlowSetTplRecord(buffer, fs_offset)
                        fs_offset += FlowSetTplRecord.size
                        tpl_records.append(record)
                    self._tpl_matcher.update_teplate(addr, fs_tpl_header.templateId, tpl_records)

            elif fs_header.flowSetId == 1:
                pass

            elif fs_header.flowSetId > 255:
                fs_template = self._tpl_matcher.match(addr, fs_header.flowSetId)
                if fs_template:
                    fs_record_offset = fs_offset
                    counter = 0
                    while fs_record_offset + fs_template.size <= offset:
                        fs = fs_template(buffer, fs_record_offset)
                        fs_record_offset += fs_template.size
                        counter += 1
                        yield (pkt_header, fs)
                    # print('=== fs_record_offset CHECK %d:%d %d-%d' % (pkt_header.count, counter, fs_record_offset, offset))
                    # print(struct.unpack_from('!{0}B'.format(offset - fs_record_offset), buffer, fs_record_offset))

            else:
                pass
