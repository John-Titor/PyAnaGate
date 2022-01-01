#!/usr/bin/env python3
#
# CAN bindings for AnaGate Ethernet-connected I/O modules.
#
# Currently only supports the CAN X1/2/4/8 units, but the protocol and design
# are open to more.
#
# Notes:
#  - CAN_DATA_IND handling requires the timestamp option, and received can_format
#    values will always have FMT_TIMESTAMP set. Disabling timestamps will result in
#    an exception when a CAN_DATA_IND message is received.
#  - AnaGate X8 firmware 2.0.17 (at least) ignores SET_CONFIG.data_confirm
#    and always reports it as 0.
#  - Analog supply reading is not mV like the analog inputs; measured data:
#
#    Counts mV       mV = 1.5254 * Counts - 10757
#    ------ ------
#    13004  9140
#    14038  9990
#    14857  12250
#    15864  13950
#    17200  15150
#    19006  18020
#    19899  20250
#    21611  22030
#    22901  24010
#

import collections
import socket
import struct
import time

# magic numbers
DEVICE_ANAGATE_CAN = (2 << 8)
REQ_IND = 0
CNF_RSP = (1 << 15)

# generic commands
CMD_OPEN = 0x1
CMD_CLOSE = 0x2
CMD_DATA = 0x3
CMD_RESET = 0x4
CMD_SET_CONFIG = 0x5
CMD_GET_CONFIG = 0x6
CMD_SET_GLOBALS = 0x7
CMD_GET_GLOBALS = 0x8
CMD_GET_INFO = 0x9
CMD_GET_STATUS = 0xA
CMD_SET_TIME = 0xB
CMD_RESTART = 0xC
CMD_ALIVE = 0xD
CMD_GET_TIME = 0xE

# CAN-specific commands
CMD_CAN_SET_FILTER = 0x20
CMD_CAN_GET_FILTER = 0x21

# digital / analog I/O commands
CMD_DIO_READ = 0x40
CMD_DIO_WRITE = 0x41
CMD_AIO_READ = 0x42
CMD_AIO_WRITE = 0x43

# CAN Format byte bits
FMT_EXTENDED = 0x01
FMT_REMOTE = 0x02
FMT_TIMESTAMP = 0x04

# CAN mode bits
MODE_NORMAL = 0x00
MODE_LOOPBACK = 0x01
MODE_PASSIVE = 0x02

# CAN Xn power supply ADC correction factors
ADC0_SCALE = 1.5254
ADC0_OFFSET = -10757

# Table definitions of known telegrams.
#
# Reserved field names:
#  'length'
#  'opcode'
#  'sequence'
#  'buffer'
#  'data'
#  'name'
#
# Format extensions:
#  '8C' - represents 1-8 bytes of CAN data, dynamically sized either from
#         the can_data initializer or from the size of the received telegram.
#
# Note that format strings here are forced to packed little-endian format
# when used.
#
# Local telegrams are indexed by name, so that they can be looked up by name
# in order to be sent. Remote telegrams are indexed by opcode so that they can
# be identified when they are received. It would seem simpler to index them all
# both ways, but sadly CAN_DATA_REQ and CAN_DATA_IND have the same opcode but
# different formats, so...
#

_local_telegrams = [
    # name                  opcode                              format      fields
    ('CAN_OPEN_REQ',        CMD_OPEN,           '',         []),
    ('CAN_CLOSE_REQ',       CMD_CLOSE,          '',         []),
    ('CAN_GET_INFO_REQ',    CMD_GET_INFO,       '',         []),
    ('CAN_DIO_WRITE_REQ',   CMD_DIO_WRITE,      'I',        ['out_bits']),
    ('CAN_DIO_READ_REQ',    CMD_DIO_READ,       '',         []),
    ('CAN_DATA_REQ',        CMD_DATA,           'IB8C',     ['can_id', 'can_format', 'can_data']),
    ('CAN_SET_CONFIG_REQ',  CMD_SET_CONFIG,     'BB',       ['data_confirm', 'data_indication']),
    ('CAN_GET_CONFIG_REQ',  CMD_GET_CONFIG,     '',         []),
    ('CAN_SET_GLOBALS_REQ', CMD_SET_GLOBALS,    'BIBBB',    ['operation_mode', 'baud_rate',
                                                             'termination', 'highspeed', 'timestamp']),
    ('CAN_GET_GLOBALS_REQ', CMD_GET_GLOBALS,    '',         []),
    ('CAN_SET_FILTER_REQ',  CMD_CAN_SET_FILTER, '16I',      ['filter_1_mask', 'filter_1_value',
                                                             'filter_2_mask', 'filter_2_value',
                                                             'filter_3_mask', 'filter_3_value',
                                                             'filter_4_mask', 'filter_4_value',
                                                             'filter_1_start', 'filter_1_end',
                                                             'filter_2_start', 'filter_2_end',
                                                             'filter_3_start', 'filter_3_end',
                                                             'filter_4_start', 'filter_4_end']),
    ('CAN_GET_FILTER_REQ',  CMD_CAN_GET_FILTER, '',         []),
    ('CAN_SET_TIME_REQ',    CMD_SET_TIME,       'II',       ['time_sec', 'time_usec']),
    ('CAN_GET_TIME_REQ',    CMD_GET_TIME,       '',         []),
    ('CAN_RESTART_REQ',     CMD_RESTART,        '',         []),
    ('CAN_AIO_READ_REQ',    CMD_AIO_READ,       '',         []),
    ('CAN_AIO_WRITE_REQ',   CMD_AIO_WRITE,      '4I',       ['out_1_mv', 'out_2_mv',
                                                             'out_3_mv', 'out_4_mv']),
]

_remote_telegrams = [
    # name                  opcode                          format      fields
    ('CAN_OPEN_CNF',        CMD_OPEN,           'B',        ['result']),
    ('CAN_CLOSE_CNF',       CMD_CLOSE,          'B',        ['result']),
    ('CAN_GET_INFO_CNF',    CMD_GET_INFO,       'BIII6s',   ['result', 'sw_version', 'hw_version',
                                                             'serial_number', 'mac_address']),
    ('CAN_DIO_WRITE_CNF',   CMD_DIO_WRITE,      'B',        ['result']),
    ('CAN_DIO_READ_CNF',    CMD_DIO_READ,       'BII',      ['result', 'in_bits', 'out_bits']),
    ('CAN_DATA_IND',        CMD_DATA,           'IB8CII',   ['can_id', 'can_format', 'can_data',
                                                             'timestamp_sec', 'timestamp_usec']),
    ('CAN_SET_CONFIG_CNF',  CMD_SET_CONFIG,     'B',        ['result']),
    ('CAN_GET_CONFIG_CNF',  CMD_GET_CONFIG,     'BBB',      ['result', 'data_confirm',
                                                             'data_indication']),
    ('CAN_SET_GLOBALS_CNF', CMD_SET_GLOBALS,    'B',        ['result']),
    ('CAN_GET_GLOBALS_CNF', CMD_GET_GLOBALS,    'BBIBBB5s', ['result', 'operation_mode', 'baud_rate',
                                                             'termination', 'highspeed',
                                                             'timestamp', 'unk']),
    ('CAN_SET_FILTER_CNF',  CMD_CAN_SET_FILTER, 'B',        ['result']),
    ('CAN_GET_FILTER_CNF',  CMD_CAN_GET_FILTER, 'B16I',     ['result',
                                                             'filter_1_mask', 'filter_1_value',
                                                             'filter_2_mask', 'filter_2_value',
                                                             'filter_3_mask', 'filter_3_value',
                                                             'filter_4_mask', 'filter_4_value',
                                                             'filter_1_start', 'filter_1_end',
                                                             'filter_2_start', 'filter_2_end',
                                                             'filter_3_start', 'filter_3_end',
                                                             'filter_4_start', 'filter_4_end']),
    ('CAN_SET_TIME_CNF',    CMD_SET_TIME,       'B',        ['result']),
    ('CAN_GET_TIME_CNF',    CMD_GET_TIME,       'BBII',     ['result', 'time_was_set', 'time_sec',
                                                             'time_usec']),
    ('CAN_RESTART_CNF',     CMD_RESTART,        'B',        ['result']),
    ('CAN_AIO_READ_CNF',    CMD_AIO_READ,       'BIIIII',   ['result', 'supply_mv', 'in_1_mv',
                                                             'in_2_mv', 'in_3_mv', 'in_4_mv']),
    ('CAN_AIO_WRITE_CNF',   CMD_AIO_WRITE,      'B',        ['result']),
]


def _ag_checksum(data):
    """
    Compute a telegram checksum.
    """
    sum = 0
    for c in data:
        sum ^= c
    return sum


class AG_telegram(object):

    _by_name = dict()
    _by_opcode = dict()
    _sequence_number = 1

    class Spec(object):
        def __init__(self, name, opcode, fmt, fields):
            self.name = name
            if name.startswith('CAN_'):
                self.opcode = opcode | DEVICE_ANAGATE_CAN
            if name.endswith('_CNF') or name.endswith('_RSP'):
                self.opcode |= CNF_RSP
            self.fmt = fmt
            self.fields = fields

    # index telegrams we might generate locally by name only
    for name, opcode, fmt, fields in _local_telegrams:
        spec = Spec(name, opcode, fmt, fields)
        _by_name[spec.name] = spec

    # index telegrams we might receive from the remote by opcode only
    for name, opcode, fmt, fields in _remote_telegrams:
        spec = Spec(name, opcode, fmt, fields)
        _by_opcode[spec.opcode] = spec

    def __init__(self, source, **kwargs):
        """
        Construct a telegram either from a spec name and initializers, or
        from a buffer containing bytes received from the remote.

        Raises:
            KeyError - the telegram name passed is not recognized
            NameError - an initializer is missing or spurious
            TypeError - the buffer passed is too small
            RuntimeError - the buffer passed contains bad data
        """
        self._fields = dict()

        # If we were given a name and some field initializers, use them
        # to create the buffer; otherwise assume we have been passed some
        # bytes off a stream.
        #
        if isinstance(source, str):
            spec = self._by_name[source]
            input_buffer = self._generate_from_spec(spec, **kwargs)
        else:
            spec = None
            input_buffer = source

        # check that the buffer is large enough
        if len(input_buffer) < 7:
            raise TypeError('insufficient data')

        # parse the header fields
        length, opcode, sequence = struct.unpack_from('<HHH', input_buffer, 0)

        # sanity-check the length
        if length > 0x200:
            raise RuntimeError('bad telegram length, stream sync probably lost')

        # check that a whole telegram has arrived
        if len(input_buffer) < (length + 2):
            raise TypeError('insufficient data')

        # copy the input data
        buffer = bytes(input_buffer[:length + 2])
        data = buffer[6:-1]

        # validate the checksum
        if _ag_checksum(buffer[2:-1]) != buffer[-1]:
            raise RuntimeError('bad telegram checksum, stream sync probably lost')

        # decode additional fields if we have a matching spec
        try:
            if spec is None:
                spec = self._by_opcode[opcode]
        except KeyError:
            pass
        else:
            # adjust the spec format for variable-sized can_data fields
            min_length = struct.calcsize('<' + spec.fmt.replace('8C', ''))
            can_length = len(data) - min_length
            if 'can_data' in spec.fields:
                if (can_length < 1) or (can_length > 8):
                    raise RuntimeError('bad CAN payload length, stream sync probably lost')
                fmt = spec.fmt.replace('8C', f'{can_length}s')
            else:
                if can_length != 0:
                    raise RuntimeError('bad telegram length, stream sync probably lost')
                fmt = spec.fmt

            # unpack additional values
            values = struct.unpack('<' + fmt, data)
            for field_name, value in zip(spec.fields, values):
                self._fields[field_name] = value

        self._fields['length'] = length
        self._fields['opcode'] = opcode
        self._fields['sequence'] = sequence
        self._fields['buffer'] = buffer
        self._fields['data'] = data
        self._fields['name'] = spec.name if spec is not None else 'unknown'

    def __getitem__(self, key):
        return self._fields[key]

    def __len__(self):
        return len(self._fields['buffer'])

    def __str__(self):
        ret = ''
        for field_name, field_value in self._fields.items():
            ret += f' {field_name} = {field_value}'
        return ret

    @classmethod
    def _generate_from_spec(cls, spec, **kwargs):
        """
        Generate a telegram in binary form from a spec and field values.
        """

        # verify that all and only required kwargs are present, and sort kwargs
        # values into canonical order
        data_args = list()
        for field_name in spec.fields:
            if field_name not in kwargs:
                raise NameError(f'missing required field initializer for {field_name}', name=field_name)
            data_args.append(kwargs[field_name])
        for kwarg in kwargs.keys():
            if kwarg not in spec.fields:
                raise NameError(f'spurious field initializer for {kwarg}', name=kwarg)

        # adjust the spec format for variable-sized can_data fields
        if 'can_data' in spec.fields:
            can_len = len(kwargs['can_data'])
            fmt = spec.fmt.replace('8C', f'{can_len}s')
        else:
            fmt = spec.fmt

        # pack the relevant fields into the buffer
        telegram_format = f'<HHH{fmt}B'
        sequence_number = cls._sequence_number
        cls._sequence_number += 1
        buffer = bytearray(struct.pack(telegram_format,
                                       struct.calcsize(telegram_format) - 2,
                                       spec.opcode,
                                       sequence_number,
                                       *data_args,
                                       0))
        # fix up the checksum
        buffer[-1] = _ag_checksum(buffer[2:-1])

        return bytes(buffer)

    @property
    def is_failure(self):
        """
        *_CNF telegrams normally have a 'result' field that is non-zero
        if the request failed
        """
        return self['result'] != 0

    @property
    def is_success(self):
        """
        *_CNF telegrams normally have a 'result' field that is non-zero
        if the request failed
        """
        return self['result'] == 0


class AG_connection(object):
    """
    Connection to an AnaGate device.
    """

    def __init__(self, device_type, host_address, port_number):
        self._device_type = device_type
        self._connected = False
        self._open = False
        self._rx_buffer = bytearray()
        self._rx_queue = collections.deque()

        self._address = f'{host_address}:{port_number}'
        self._socket = socket.create_connection((host_address, port_number), timeout=2.0)
        self._connected = True
        self._socket.settimeout(0.05)

        self.command(f'{self._device_type}_OPEN_REQ')
        self._open = True

    def send(self, name, **kwargs):
        """
        Construct and send a telegram.
        """
        assert self._connected

        tel = AG_telegram(name, **kwargs)
        self._socket.sendall(tel['buffer'])
        # print(f'sent {tel}')
        # print(f'sent {tel["buffer"]}')

    def _recv(self, deadline=None):
        """
        Wait for a telegram or deadline
        """
        while True:
            try:
                tel = AG_telegram(self._rx_buffer)
                # print(f'recv {tel}')
                # print(f'recv {tel.buffer}')
                del self._rx_buffer[:len(tel)]
                return tel
            except TypeError:
                # we need more bytes
                pass
            try:
                if time.time() >= deadline:
                    return None
                self._rx_buffer.extend(self._socket.recv(512))
            except socket.timeout:
                # loop back and try again
                pass

    def recv(self, expect=None, timeout=0.5):
        """
        Receive a telegram.

        If expect specifies a telegram by name, only a telegram of that type
        will be returned.

        If timeout is not specified, we will poll for a telegram and return
        immediately. Otherwise, if no telegram is received by the deadline,
        None is returned.

        CAN_DATA_IND telegrams received while waiting for other telegrams
        are buffered to avoid missing them.
        """
        deadline = time.time() + timeout
        while True:
            # if we're looking for a CAN message and we have one queued, return it
            if expect == 'CAN_DATA_IND':
                try:
                    return self._rx_queue.popleft()
                except IndexError:
                    pass

            # wait for something to come in
            tel = self._recv(deadline=deadline)

            # timed out?
            if tel is None:
                return None

            # if we are trying to match something, did we get it?
            if expect is not None:
                if tel['name'] == expect:
                    return tel

            # if it's a CAN message, buffer it for later
            if tel['name'] == 'CAN_DATA_IND':
                self._rx_queue.append(tel)

    def command(self, name, timeout=0.5, **kwargs):
        """
        Send a request telegram and return the confirmation telegram. It's assumed that
        the reply telegram has a result field, and that its name corresponds to
        the request telegram.
        """
        expect = name.replace('_REQ', '_CNF')
        self.send(name, **kwargs)
        rsp = self.recv(expect=expect, timeout=timeout)
        if rsp.is_failure:
            raise RuntimeError(f'error executing {name}')
        return rsp

    def close(self):
        """
        shut down and close the connection
        """
        if self._open:
            self.send(f'{self._device_type}_CLOSE_REQ')
            # don't wait for a response, it never arrives and we would hang
            self._open = False
        if self._connected:
            self._socket.close()
            self._connected = False

    def __del__(self):
        self.close()


class AG_CAN_connection(AG_connection):
    """
    Connection to a specific interface on an AnaGate CAN Xn device.
    """

    _port_map = {
        'A': 5001,
        'B': 5101,
        'C': 5201,
        'D': 5301,
        'E': 5401,
        'F': 5501,
        'G': 5601,
        'H': 5701,
    }

    def __init__(self, host_address, port_name):
        self._dio_outs = None
        self._aio_outs = None

        try:
            port_number = self._port_map[port_name]
        except KeyError:
            raise RuntimeError(f'bad port name "{port_name}" (must be A-G)')

        super().__init__('CAN', host_address, port_number)

    def configure(self, baud_rate,
                  loopback_mode=False,
                  passive_mode=False,
                  enable_termination=False,
                  filters=None):
        """
        Configure the CAN interface.

        Loopback mode overrides passive mode; if neither are specified the interface operates
        normally.

        Filters are specified in a dictionary:
        {
            'masks': (mask0, mask1, mask2, mask3),
            'values': (value0, value1, value2, value3),
            'ranges': ((start0, end0), (start1, end1), (start2, end2), (start3, end3))
        }
        """
        self.command('CAN_SET_CONFIG_REQ', data_confirm=0, data_indication=1)
        self.command('CAN_SET_GLOBALS_REQ',
                     operation_mode=MODE_LOOPBACK if loopback_mode else MODE_PASSIVE if passive_mode else MODE_NORMAL,
                     baud_rate=baud_rate,
                     termination=enable_termination,
                     highspeed=1 if filters is None else 0,
                     timestamp=1)
        if filters is None:
            self.command('CAN_SET_FILTER_REQ',
                         filter_1_mask=0, filter_1_value=0,
                         filter_2_mask=0, filter_2_value=0,
                         filter_3_mask=0, filter_3_value=0,
                         filter_4_mask=0, filter_4_value=0,
                         filter_1_start=0, filter_1_end=0x1FFFFFFF,
                         filter_2_start=0, filter_2_end=0x1FFFFFFF,
                         filter_3_start=0, filter_3_end=0x1FFFFFFF,
                         filter_4_start=0, filter_4_end=0x1FFFFFFF)
        else:
            self.command('CAN_SET_FILTER_REQ',
                         filter_1_mask=filters['masks'][0], filter_1_value=filters['values'][0],
                         filter_2_mask=filters['masks'][1], filter_2_value=filters['values'][1],
                         filter_3_mask=filters['masks'][2], filter_3_value=filters['values'][2],
                         filter_4_mask=filters['masks'][3], filter_4_value=filters['values'][3],
                         filter_1_start=filters['ranges'][0][0], filter_1_end=filters['ranges'][0][1],
                         filter_2_start=filters['ranges'][1][0], filter_2_end=filters['ranges'][1][1],
                         filter_3_start=filters['ranges'][2][0], filter_3_end=filters['ranges'][2][1],
                         filter_4_start=filters['ranges'][3][0], filter_4_end=filters['ranges'][3][1])

    def set_digital_out(self, pin, value):
        """
        Set a GPIO in digital mode; disables analog outputs.
        """
        if pin not in (1, 2, 3, 4):
            raise IndexError('invalid output pin number')
        pin -= 1
        self._aio_outs = None
        if self._dio_outs is None:
            self._dio_outs = 0
        if value:
            self._dio_outs |= 1 << pin
        else:
            self._dio_outs &= ~(1 << pin)
        self.command('CAN_DIO_WRITE_REQ', out_bits=self._dio_outs)

    def get_digital_in(self, pin):
        """
        Read a GPIO in digital mode.
        """
        if pin not in (1, 2, 3, 4):
            raise IndexError('invalid input pin number (must be 1-4)')
        pin -= 1
        tel = self.command('CAN_DIO_READ_REQ')
        return 1 if (tel["in_bits"] & (1 << pin)) else 0

    def set_analog_out(self, pin, value_mv):
        """
        Set a GPIO in analog mode; disables digital outputs.
        """
        if pin not in (1, 2, 3, 4):
            raise IndexError('invalid output pin number (must be 1-4)')
        pin -= 1
        if (value_mv < 0) | (value_mv > 24000):
            raise ValueError('invalid output voltage (must be 0-24000mV')
        self._dio_outs = None
        if self._aio_outs is None:
            self._aio_outs = [0, 0, 0, 0]
        self._aio_outs[pin] = value_mv
        self.command('CAN_AIO_WRITE_REQ',
                     out_1_mv=self._aio_outs[0],
                     out_2_mv=self._aio_outs[1],
                     out_3_mv=self._aio_outs[2],
                     out_4_mv=self._aio_outs[3])

    def get_analog_in(self, pin):
        """
        Read a GPIO in analog mode, returns voltage in mV.

        Pin 0 is the supply voltage, and scaling is applied as required
        to yield mV output.
        """
        if pin not in (0, 1, 2, 3, 4):
            raise IndexError('invalid input pin number (must be 0-4)')
        tel = self.command('CAN_AIO_READ_REQ')
        return (int(tel['supply_mv'] * ADC0_SCALE + ADC0_OFFSET) if pin == 0 else
                tel['in_1_mv'] if pin == 1 else
                tel['in_2_mv'] if pin == 2 else
                tel['in_3_mv'] if pin == 3 else
                tel['in_4_mv'])

    def send_can(self, can_id, data, extended_id=False):
        """
        Convenience wrapper for sending CAN data.
        """
        self.send('CAN_DATA_REQ',
                  can_id=can_id,
                  can_format=FMT_EXTENDED if extended_id else 0,
                  can_data=data)

    def recv_can(self, expect_id=None, timeout=0.5):
        """
        Convenience wrapper for receiving CAN data.

        Returns a dictionary:
        {
            'can_id': 0xNNN,
            'extended_id': True/False,
            'data': bytes,
            'timestamp_us': receive timestamp
        }

        XXX timeout behaviour is broken in the case of spammy traffic
        """
        while True:
            tel = self.recv(expect='CAN_DATA_IND', timeout=timeout)
            if tel is not None:
                if expect_id is not None:
                    if tel['can_id'] != expect_id:
                        continue
            else:
                return None
            return {'can_id':       tel['can_id'],
                    'extended_id':  True if (tel['can_format'] & FMT_EXTENDED) else False,
                    'data':         tel['can_data'],
                    'timestamp':    tel['timestamp_sec'] * 1000000 + tel['timestamp_usec']}


if __name__ == '__main__':
    # constructors and test vectors for CAN messages
    tel = AG_telegram('CAN_OPEN_REQ')
    tel = AG_telegram(b'\x06\x00\x01\x82\x02\x00\x00\x81')                      # CAN_OPEN_CNF
    tel = AG_telegram('CAN_CLOSE_REQ')
#    tel = AG_telegram('CAN_CLOSE_CNF')                                          # never see this
    tel = AG_telegram('CAN_GET_INFO_REQ')
    tel = AG_telegram(b'\x18\x00\t\x82\x02\x00\x00\x11\x00\x02\x00\x00\x01' +
                      b'\x11\x00\xe0\x10\x02\x01\xb8\x8f\x14\x00\x10\xe0\xaa')  # CAN_GET_INFO_CNF
    tel = AG_telegram('CAN_DIO_WRITE_REQ', out_bits=0xf)
    tel = AG_telegram(b'\x06\x00A\x82\x02\x00\x00\xc1')                         # CAN_DIO_WRITE_CNF
    tel = AG_telegram('CAN_DIO_READ_REQ')
    tel = AG_telegram(b'\x0e\x00@\x82\x02\x00\x00\x00\x00\x00\x00\x05\x00' +
                      b'\x00\x00\xc5')                                          # CAN_DIO_READ_CNF
    tel = AG_telegram('CAN_DATA_REQ', can_id=0x780, can_format=0, can_data=b'abcdE')
#    tel = AG_telegram('CAN_DATA_CNF')                                           # not used
    tel = AG_telegram(b'\x17\x00\x03\x02\x1e\x00p\x00\x00\x00\x04123a5\x00' +
                      b'\x00\x00\x00\xad\x11\x00\x00\xb3')                      # CAN_DATA_IND
#    tel = AG_telegram('CAN_DATA_RSP', result=AG_result.RES_SUCCESS)               # not used
    tel = AG_telegram('CAN_SET_CONFIG_REQ', data_confirm=0, data_indication=1)
    tel = AG_telegram(b'\x06\x00\x05\x82\x02\x00\x00\x85')                      # CAN_SET_CONFIG_CNF
    tel = AG_telegram('CAN_GET_CONFIG_REQ')
    tel = AG_telegram(b'\x08\x00\x06\x82\x02\x00\x00\x00\x01\x87')              # CAN_GET_CONFIG_CNF
    tel = AG_telegram('CAN_SET_GLOBALS_REQ', operation_mode=1, baud_rate=500000, termination=0, highspeed=0, timestamp=1)
    tel = AG_telegram(b'\x06\x00\x07\x82\x02\x00\x00\x87')                      # CAN_SET_GLOBALS_CNF
    tel = AG_telegram('CAN_GET_GLOBALS_REQ')
    tel = AG_telegram(b'\x13\x00\x08\x82\x02\x00\x00\x01 \xa1\x07\x00\x01' +
                      b'\x00\x01\x01@\x00\x00\x00N')                            # CAN_GET_GLOBALS_CNF
    tel = AG_telegram('CAN_SET_FILTER_REQ', filter_1_mask=0,
                                            filter_1_value=0,
                                            filter_2_mask=0,
                                            filter_2_value=0,
                                            filter_3_mask=0,
                                            filter_3_value=0,
                                            filter_4_mask=0,
                                            filter_4_value=0,
                                            filter_1_start=0,
                                            filter_1_end=0,
                                            filter_2_start=0,
                                            filter_2_end=0,
                                            filter_3_start=0,
                                            filter_3_end=0,
                                            filter_4_start=0,
                                            filter_4_end=0)
    tel = AG_telegram(b'\x06\x00 \x82\x02\x00\x00\xa0')                         # CAN_SET_FILTER_CNF
    tel = AG_telegram('CAN_GET_FILTER_REQ')
    tel = AG_telegram(b'F\x00!\x82\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                      b'\x00\x00\x00\x00\x00\xa1')                              # CAN_GET_FILTER_CNF
    tel = AG_telegram('CAN_SET_TIME_REQ', time_sec=0, time_usec=0)
    tel = AG_telegram(b'\x06\x00\x0b\x82\x1e\x00\x00\x97')                      # CAN_SET_TIME_CNF
    tel = AG_telegram('CAN_GET_TIME_REQ')
    tel = AG_telegram(b'\x0f\x00\x0e\x82\x1f\x00\x00\x01\x00\x00\x00\x00\xdd' +
                      b'\r\x00\x00B')                                           # CAN_GET_TIME_CNF
    tel = AG_telegram('CAN_RESTART_REQ')
    tel = AG_telegram(b'\x06\x00\x0c\x82"\x00\x00\xac')                         # CAN_RESTART_CNF
    tel = AG_telegram('CAN_AIO_READ_REQ')
    tel = AG_telegram(b'\x1a\x00B\x82 \x00\x00\xca<\x00\x00L\x00\x00\x00L' +
                      b'\x00\x00\x00L\x00\x00\x00S\x00\x00\x00\t')              # CAN_AIO_READ_CNF
    tel = AG_telegram('CAN_AIO_WRITE_REQ', out_1_mv=0, out_2_mv=0, out_3_mv=0, out_4_mv=0)
    tel = AG_telegram(b'\x06\x00C\x82!\x00\x00\xe0')                            # CAN_AIO_WRITE_CNF

    # live tests with a CAN X8 on the local network
    conn = AG_CAN_connection('192.168.1.112', 'A')
    print(f'connected to {conn._address}')

    reply = conn.command('CAN_GET_INFO_REQ')
    print(f'sw_version {(reply["sw_version"] >> 16) & 0xff}.{(reply["sw_version"] >> 8) & 0xff}.{reply["sw_version"] & 0xff}')
    print(f'hw_version {(reply["hw_version"] >> 16) & 0xf}.{(reply["hw_version"] >> 8) & 0xff}.{reply["hw_version"] & 0xff}')
    print(f'serial     {reply["serial_number"]:08X}')
    print(f'MAC        {reply["mac_address"].hex(sep=":")}')

    conn.command('CAN_DIO_WRITE_REQ', out_bits=0x5)
    reply = conn.command('CAN_DIO_READ_REQ')
    print(f'input bits {reply["in_bits"]:#x}')
    print(f'outut bits {reply["out_bits"]:#x}')
    assert reply["out_bits"] == 0x5

    conn.command('CAN_SET_CONFIG_REQ', data_confirm=0, data_indication=1)
    reply = conn.command('CAN_GET_CONFIG_REQ')
    print(f'data_confirm    {reply["data_confirm"]}')
    print(f'data_indication {reply["data_indication"]}')
    assert reply["data_confirm"] == 0
    assert reply["data_indication"] == 1

    conn.command('CAN_SET_GLOBALS_REQ', operation_mode=1, baud_rate=500000, termination=1, highspeed=0, timestamp=1)
    try:
        conn.command('CAN_SET_GLOBALS_REQ', operation_mode=11, baud_rate=500000, termination=1, highspeed=0, timestamp=1)
    except RuntimeError:
        pass
    else:
        raise RuntimeError('expected AG_command_error for illegal operation')
    reply = conn.command('CAN_GET_GLOBALS_REQ')
    print(f'operation_mode {reply["operation_mode"]}')
    print(f'baud_rate      {reply["baud_rate"]}')
    print(f'termination    {reply["termination"]}')
    print(f'highspeed      {reply["highspeed"]}')
    print(f'timestamp      {reply["timestamp"]}')

    conn.command('CAN_SET_FILTER_REQ',
                 filter_1_mask=0,
                 filter_1_value=0,
                 filter_2_mask=0,
                 filter_2_value=0,
                 filter_3_mask=0,
                 filter_3_value=0,
                 filter_4_mask=0,
                 filter_4_value=0,
                 filter_1_start=0,
                 filter_1_end=0x1FFFFFFF,
                 filter_2_start=0,
                 filter_2_end=0x1FFFFFFF,
                 filter_3_start=0,
                 filter_3_end=0x1FFFFFFF,
                 filter_4_start=0,
                 filter_4_end=0x1FFFFFFF)
    reply = conn.command('CAN_GET_FILTER_REQ')
    print(f'filter_1_mask   {reply["filter_1_mask"]:#x}')
    print(f'filter_1_value  {reply["filter_1_value"]:#x}')
    print(f'filter_2_mask   {reply["filter_2_mask"]:#x}')
    print(f'filter_2_value  {reply["filter_2_value"]:#x}')
    print(f'filter_3_mask   {reply["filter_3_mask"]:#x}')
    print(f'filter_3_value  {reply["filter_3_value"]:#x}')
    print(f'filter_4_mask   {reply["filter_4_mask"]:#x}')
    print(f'filter_4_value  {reply["filter_4_value"]:#x}')
    print(f'filter_1_start  {reply["filter_1_start"]:#x}')
    print(f'filter_1_end    {reply["filter_1_end"]:#x}')
    print(f'filter_2_start  {reply["filter_2_start"]:#x}')
    print(f'filter_2_end    {reply["filter_2_end"]:#x}')
    print(f'filter_3_start  {reply["filter_3_start"]:#x}')
    print(f'filter_3_end    {reply["filter_3_end"]:#x}')
    print(f'filter_4_start  {reply["filter_4_start"]:#x}')
    print(f'filter_4_end    {reply["filter_4_end"]:#x}')

    conn.command('CAN_SET_TIME_REQ', time_sec=0, time_usec=0)
    reply = conn.command('CAN_GET_TIME_REQ')
    print(f'time_was_set {reply["time_was_set"]}')
    print(f'time_sec     {reply["time_sec"]}')
    print(f'time_usec    {reply["time_usec"]}')
    assert reply["time_was_set"]

    # send a CAN message; we are in loopback mode so expect it to come right back
    conn.send('CAN_DATA_REQ', can_id=0x70, can_format=0, can_data=b'123a5')
    echo = conn.recv('CAN_DATA_IND')
    print(f'ECHO {echo}')
    assert echo["can_id"] == 0x70
    assert echo["can_data"] == b'123a5'

    reply = conn.command('CAN_AIO_READ_REQ')
    print(f'supply_mv {reply["supply_mv"]}')
    print(f'in_1_mv   {reply["in_1_mv"]}')
    print(f'in_2_mv   {reply["in_2_mv"]}')
    print(f'in_3_mv   {reply["in_3_mv"]}')
    print(f'in_4_mv   {reply["in_4_mv"]}')
    conn.command('CAN_AIO_WRITE_REQ', out_1_mv=3000, out_2_mv=5000, out_3_mv=7000, out_4_mv=9000)

    # turn off loopback and verify that we don't get an echo
    conn.command('CAN_SET_GLOBALS_REQ', operation_mode=0, baud_rate=500000, termination=1, highspeed=0, timestamp=1)
    conn.send('CAN_DATA_REQ', can_id=0x70, can_format=0, can_data=b'123aa')
    echo = conn.recv('CAN_DATA_IND')
    if echo is not None:
        raise RuntimeError('unwanted loopback message')

    # expect that out1 and in1 are connected, verify digital and analog loopback
    try:
        conn.set_digital_out(pin=1, value=0)
        time.sleep(0.05)
        if conn.get_digital_in(pin=1) != 0:
            raise RuntimeError('digital loopback 0 fail')
        if conn.get_analog_in(pin=1) > 1000:
            raise RuntimeError('analog sniff of digital 0 fail')
        conn.set_digital_out(pin=1, value=1)
        time.sleep(0.05)
        if conn.get_digital_in(pin=1) != 1:
            raise RuntimeError('digital loopback 1 fail')
        if conn.get_analog_in(pin=1) < 1000:
            raise RuntimeError('analog sniff of digital 1 fail')

        for val in (500, 1000, 2000, 4000, 8000, 10000):
            conn.set_analog_out(pin=1, value_mv=val)
            time.sleep(0.05)
            delta = conn.get_analog_in(pin=1) - val
            if (delta < -150) or (delta > 150):
                raise RuntimeError(f'analog loopback error {delta} for {val}')
    except RuntimeError as e:
        print(f'GPIO loopback failed ({str(e)}), maybe out1 and in1 are not connected')

    # exercise the convenience APIs
    conn.configure(500000, loopback_mode=True)
    conn.send_can(0x80, b'abcdefg')
    msg = conn.recv_can(expect_id=0x80)
    if msg is not None:
        assert msg['can_id'] == 0x80
        assert msg['data'] == b'abcdefg'
    else:
        raise RuntimeError('CAN loopback failure')

    conn.command('CAN_RESTART_REQ')
    conn.close()
    print('closed')
