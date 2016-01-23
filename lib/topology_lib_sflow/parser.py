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

from re import search
from logging import getLogger


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


# Need to update or add a new method
# to handle long format output from sflowtool
def parse_sflowtool(raw_output):
    """
    Parse the sflowtool output command raw output.

    :param str raw_output: bash raw result string.
    :rtype: dict
    :return: All sflow packets seen at the collector parsed
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
    """

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
                            'out_ucastPkts', 'out_mcastPkts', 'out_bcastPkts',
                            'out_discards', 'out_errors', 'if_promiscuousMode']

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


__all__ = [
    'parse_sflowtool'
]
