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

        {
            'datagrams':
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
                            'sampleType_tag':'0:2'
                            'sampleType':'COUNTERSSAMPLE'
                            'sampleSequenceNo':'1'
                            ....(fields in sample)
                        },
                    ....(all the samples captured in the datagram)

                    'cntr_samples': 1,
                    'flow_samples': 1,
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
                            'sampleType_tag':'0:2'
                            'sampleType':'COUNTERSSAMPLE'
                            'sampleSequenceNo':'2'
                            ....(fields in sample)
                        },
                    ....(all the samples captured in the datagram)

                    'cntr_samples': 1,
                    'flow_samples': 1
                    ]
                },
                ....(all the datagrams captured)
            ]    
            'number_of_datagrams': 2
        }
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

        result = {}
        result['datagrams'] = []
        result['number_of_datagrams'] = 0

        # Strings to be used while matching datagrams and samples
        # in the output from sflowtool
        start_datagram = 'startDatagram =================================\n'
        end_datagram = 'endDatagram   =================================\n'
        start_sample = 'startSample ----------------------\n'
        end_sample = 'endSample   ----------------------\n'

        # Regex string for identifying start/end of datagrams & samples
        finder = r'{}(.*?){}'

        # Regex to parse datagram attributes
        datagram_info_re = (
            r'datagramSourceIP\s(?P<datagramSourceIP>.+)\s'
            r'datagramSize\s(?P<datagramSize>.+)\s'
            r'unixSecondsUTC\s(?P<unixSecondsUTC>.+)\s'
            r'datagramVersion\s(?P<datagramVersion>.+)\s'
            r'agentSubId\s(?P<agentSubId>.+)\s'
            r'agent\s(?P<agent>.+)\s'
            r'packetSequenceNo\s(?P<packetSequenceNo>.+)\s'
            r'sysUpTime\s(?P<sysUpTime>.+)\s'
            r'samplesInPacket\s(?P<samplesInPacket>\d+)\s'
        )

        # Regex for matching attributes inside a sample
        attribute_re = '((.+) (.+))'

        # Make a list of datagrams from the sflowtool raw output
        datagrams = findall(
            finder.format(start_datagram, end_datagram), raw_output, DOTALL)

        for datagram in datagrams:

            # Get the datagram specific attributes and form a dict
            re_result = match(datagram_info_re, datagram, DOTALL)
            datagram_dict = re_result.groupdict()

            # Initialize sample specific data inside the datagram_dict
            datagram_dict['samples'] = []
            datagram_dict['flow_samples'] = 0
            datagram_dict['cntr_samples'] = 0

            # Get list of samples from within the datagram
            samples = findall(
                finder.format(start_sample, end_sample), datagram, DOTALL)

            for sample in samples:
                sample_lines = sample.splitlines()
                sample_dict = {}

                # Match the attributes of each sample and populate
                # into the sample_dict
                for sample_line in sample_lines:
                    attribute = match(attribute_re, sample_line)
                    sample_dict[attribute.group(2)] = attribute.group(3)

                # Add the sample to the list of samples under the datagram
                datagram_dict['samples'].append(sample_dict)

                # Increment respective counters based on type of sample
                if sample_dict['sampleType'] == 'FLOWSAMPLE':
                    datagram_dict['flow_samples'] += 1
                elif sample_dict['sampleType'] == 'COUNTERSSAMPLE':
                    datagram_dict['cntr_samples'] += 1

            # Add the parsed datagram to result and increment count
            # of datagrams
            result['datagrams'].append(datagram_dict)
            result['number_of_datagrams'] += 1

        return result


__all__ = [
    'parse_sflowtool'
]
