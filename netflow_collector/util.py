import struct
import collections


def structuple(typename, format, field_names, converters=None):
    """Создаёт химеру из struct и namedtuple.

        middleware - {'attr_name': converter} позволяет задать преобразования
    для полей из сырого значения в определённый тип.

        Example:

        >>> from ipaddress import ip_address
        >>> s = structuple('Test', '!LH', 'addr port', {'addr': ip_address})
        >>> print(s(b'abcd12'))
        Test(addr=IPv4Address('97.98.99.100'), port=12594)
    """
    nt = collections.namedtuple(typename, field_names)
    st = struct.Struct(format)

    def new_basic(_cls, buffer, offset=0):
        args = st.unpack_from(buffer, offset=offset)
        self = super(nt, _cls).__new__(_cls, args)
        return self

    def new_converters(_cls, buffer, offset=0):
        args = st.unpack_from(buffer, offset=offset)
        self = super(nt, _cls).__new__(_cls, args)
        replacement = {}
        for attr, convert in converters.items():
            if hasattr(self, attr):
                replacement[attr] = convert(getattr(self, attr))
        self = self._replace(**replacement)
        return self

    __new__ = new_converters if converters else new_basic

    return type(typename, (nt,), {'size': st.size, 'format': st.format, '__new__': __new__})
