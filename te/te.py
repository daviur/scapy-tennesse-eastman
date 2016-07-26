# The MIT License (MIT)
#
# Copyright (c) 2016 David I Urbina
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""Scapy Dissector for CIP messages of the Field Communication Network of the
Tennessee Eastman Testbed at the National Institute of Standards and Technology"""

from scapy import all as scapy_all

import cip


class LEIEEEFloatField(scapy_all.Field):
    def __init__(self, name, default):
        scapy_all.Field.__init__(self, name, default, "<f")


class TE_FCN_SENSORS(scapy_all.Packet):
    name = "TE_FCN_SENSORS"
    fields_desc = [
        scapy_all.LEShortField('group', 0),
        LEIEEEFloatField('field0', 0),
        LEIEEEFloatField('field1', 0),
        LEIEEEFloatField('field2', 0),
        LEIEEEFloatField('field3', 0),
        LEIEEEFloatField('field4', 0),
        LEIEEEFloatField('field5', 0),
        LEIEEEFloatField('field6', 0),
        LEIEEEFloatField('reactor_pressure', 0),
        LEIEEEFloatField('field8', 0),
        LEIEEEFloatField('reactor_temperature', 0),
        LEIEEEFloatField('field10', 0),
        LEIEEEFloatField('field11', 0),
        LEIEEEFloatField('field12', 0),
        LEIEEEFloatField('field13', 0),
        LEIEEEFloatField('field14', 0),
        LEIEEEFloatField('field15', 0),
        LEIEEEFloatField('field16', 0),
        LEIEEEFloatField('field17', 0),
        LEIEEEFloatField('field18', 0),
        LEIEEEFloatField('field19', 0),
        LEIEEEFloatField('field20', 0),
        LEIEEEFloatField('field21', 0),
        LEIEEEFloatField('field22', 0),
        LEIEEEFloatField('field23', 0),
        LEIEEEFloatField('field24', 0),
        LEIEEEFloatField('field25', 0),
        LEIEEEFloatField('field26', 0),
        LEIEEEFloatField('field27', 0),
        LEIEEEFloatField('field28', 0),
        LEIEEEFloatField('field29', 0),
        LEIEEEFloatField('field30', 0),
        LEIEEEFloatField('field31', 0),
        LEIEEEFloatField('field32', 0),
        LEIEEEFloatField('field33', 0),
        LEIEEEFloatField('field34', 0),
        LEIEEEFloatField('field35', 0),
        LEIEEEFloatField('field36', 0),
        LEIEEEFloatField('field37', 0),
        LEIEEEFloatField('field38', 0),
        LEIEEEFloatField('field39', 0),
        LEIEEEFloatField('field40', 0),
        LEIEEEFloatField('field41', 0),
    ]


CONTROL_TAGS = {
    0x1: 'tag1',
    0x2: 'tag2',
    0x3: 'tag3',
    0x4: 'tag4',
    0x5: 'tag5',
    0x6: 'purge_valve',
    0x7: 'tag7',
    0x8: 'tag8',
    0x9: 'tag9',
    0xA: 'reactor_cooling_water_flow',
    0xB: 'tag11',
    0xC: 'tag12'
}


class TE_FCN_CONTROLS(scapy_all.Packet):
    name = "TE_FCN_CONTROLS"
    fields_desc = [
        scapy_all.IntField('constant', 0),
        LEIEEEFloatField('value', 0),
    ]


def extend_cip_bindings(self, payload):
    if self.direction == 1 and self.service == 0x4c and len(payload) >= 488:
        return TE_FCN_SENSORS
    return scapy_all.Packet.guess_payload_class(self, payload)


cip.CIP.guess_payload_class = extend_cip_bindings 
scapy_all.bind_layers(cip.CIP, TE_FCN_CONTROLS, direction=0, service=0x4d)
