# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Parse sflowtool commands with output to a Python dictionary.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from re import search, findall, DOTALL, match
from logging import getLogger
from collections import OrderedDict


log = getLogger(__name__)


def parse_pid(response):
    """
    Parse PID shell output using a regular expression.

    :param str response: Output of a shell forking a subprocess.
    """
    assert response

    pid_regex = r'\[\d*\]\s+(?P<pid>\d+)'

    regex_result = search(pid_regex, response)
    if not regex_result:
        log.debug('Failed to parse pid from:\n{}'.format(response))
        raise Exception('PID regular expression didn\'t match.')

    return int(regex_result.groupdict()['pid'])


def parse_sflowtool(raw_output, mode):
    """
    Parse the sflowtool output command raw output.

    :param str raw_output: bash raw result string.
    :rtype: dict
    :return: In the line mode, all sflow packets seen at the collector parsed
             in the form:

     ::

        {
            'flow_count':10
            'sample_count':5
            'packets':[
                {
                    'packet_type':'FLOW',
                    'agent_address':'10.10.11.1',
                    'in_port':8,
                    ....(fields in FLOW packet)
                },
                {
                    'packet_type':'CNTR',
                    'agent_address':'10.10.11.1',
                    'if_index':2,
                    ....(fields in CNTR packet)
                }
            ]
        }


            In the detail mode, all sflow packets seen at the collector parsed
            in the form:

     ::

        [
            {
                'datagramSourceIP':'10.10.12.1',
                'datagramSize':'924',
                'unixSecondsUTC':'1473185811',
                ....(fields in datagram packet)

                'samples':
                            [
                                {                
                                    'sampleType_tag':'0:1'
                                    'sampleType':'FLOWSAMPLE'
                                    'headerLen':'64'
                                    ....(fields in sample)
                                },
                                {                
                                    'sampleType_tag':'0:1'
                                    'sampleType':'FLOWSAMPLE'
                                    'headerLen':'64'
                                    ....(fields in sample)
                                },
                                ....(all the samples captured in the datagram)
                            ]
            },
            {
                'datagramSourceIP':'10.10.12.1',
                'datagramSize':'924',
                'unixSecondsUTC':'1473185811',
                ....(fields in datagram packet)

                'samples':
                            [
                                {                
                                    'sampleType_tag':'0:1'
                                    'sampleType':'FLOWSAMPLE'
                                    'headerLen':'64'
                                    ....(fields in sample)
                                },
                                {                
                                    'sampleType_tag':'0:1'
                                    'sampleType':'FLOWSAMPLE'
                                    'headerLen':'64'
                                    ....(fields in sample)
                                },
                                ....(all the samples captured in the datagram)
                            ]
            },
            ....(all the datagrams captured)
        ]
    """

    if mode == 'line':
        # Refer https://github.com/sflow/sflowtool regarding below fields
        flow_packet_fields = ['packet_type', 'agent_address', 'in_port',
                              'out_port', 'src_mac', 'dst_mac',
                              'eth_type', 'in_vlan', 'out_vlan',
                              'src_ip', 'dst_ip', 'ip_protocol', 'ip_tos',
                              'ip_ttl', 'icmp_type', 'icmp_code', 'tcp_flags',
                              'packet_size', 'ip_size', 'sampling_rate']
        sample_packet_fields = ['packet_type', 'agent_address', 'if_index',
                                'if_type', 'if_speed', 'if_direction',
                                'if_status', 'in_octets', 'in_ucastPkts',
                                'in_mcastPkts', 'in_bcastPkts', 'in_discards',
                                'in_errors', 'in_unknownProtos', 'out_octets',
                                'out_ucastPkts', 'out_mcastPkts',
                                'out_bcastPkts', 'out_discards', 'out_errors',
                                'if_promiscuousMode']

        output = raw_output.splitlines()
        flow_count = 0
        sample_count = 0
        result = {}
        packets = []

        for line in output:
            packet = {}  # sFlow packet information
            sflow_packet = line.split(",")
            if sflow_packet[0] == 'FLOW':
                assert len(sflow_packet) == len(flow_packet_fields)
                for field in range(len(sflow_packet)):
                    packet[flow_packet_fields[field]] = sflow_packet[field]
                flow_count = flow_count + 1
                packets.append(packet)
            elif sflow_packet[0] == 'CNTR':
                assert len(sflow_packet) == len(sample_packet_fields)
                for field in range(len(sflow_packet)):
                    packet[sample_packet_fields[field]] = sflow_packet[field]
                sample_count = sample_count + 1
                packets.append(packet)

        result['flow_count'] = flow_count
        result['sample_count'] = sample_count
        result['packets'] = packets
        return result

    elif mode == 'detail':

        start_datagram = 'startDatagram =================================\n'
        end_datagram = 'endDatagram   =================================\n'

        start_sample = 'startSample ----------------------\n'
        end_sample = 'endSample   ----------------------\n'

        finder = r'{}(.*?){}'

        datagrams = findall(
            finder.format(start_datagram, end_datagram), raw_output, DOTALL)

        result = []
        attribute_re = '((?!startSample|endSample)(.+?) (.+))'
        start_sample_re = 'startSample .+'
        end_sample_re = 'endSample .+'

        for datagram in datagrams:

            result.append(OrderedDict())
            datagram_lines = datagram.splitlines()
            sample_flag = False

            for datagram_line in datagram_lines:

                attribute = match(attribute_re, datagram_line)
                start_sample = match(start_sample_re, datagram_line)
                end_sample = match(end_sample_re, datagram_line)

                if attribute is not None:
                    if sample_flag:
                        result[-1]['samples'][-1][attribute.group(2)] = \
                            attribute.group(3)
                        continue
                    else:
                        result[-1][attribute.group(2)] = attribute.group(3)
                        continue

                elif start_sample is not None:
                    if sample_flag:
                        raise Exception('Nested sample found.')
                    sample_flag = True

                    if 'samples' not in result[-1].keys():
                        result[-1]['samples'] = [OrderedDict()]
                        continue
                    else:
                        result[-1]['samples'].append(OrderedDict())

                elif end_sample is not None:
                    if not sample_flag:
                        raise Exception(
                            'Ending of sample found without \
                            it being started before.'
                        )
                    sample_flag = False

                else:
                    raise Exception('Uknown element found.')
        return result


__all__ = [
    'parse_sflowtool'
]
