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

"""Sniffing functions to be used as parameter prn of the "sniff" command in
Scapy 2.3.1.
"""

from __future__ import print_function, division

from cip import CIP_Path
from te import TE_FCN_SENSORS, TE_FCN_CONTROLS, CONTROL_TAGS

counter = 0

def read_te_sensors(packet):
    global counter
    if TE_FCN_SENSORS in packet:
        counter += 1
        return str(counter)
	#reactor_temperature = packet[TE_FCN_SENSORS].reactor_temperature
        #reactor_pressure = packet[TE_FCN_SENSORS].reactor_pressure
        #return 'pressure: {:2f} temperature: {:2f}'.format(reactor_pressure, reactor_temperature)


def read_te_controls(packet):
    if TE_FCN_CONTROLS in packet:
        return '{}: {:2f}'.format(__get_tag_name(packet), packet[TE_FCN_CONTROLS].value)


def __get_tag_name(packet):
    return CONTROL_TAGS[ord(packet[CIP_Path].path[-1])]
