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
Test the sflow parsing module.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from topology_lib_sflow.parser import parse_sflowtool

from deepdiff import DeepDiff


def test_sflowtool():

    raw = """\
FLOW,10.10.12.1,424,1073741823,0a5e44a7e381,7072cfa36a9a,0x0800,0,0,\
10.10.10.2,10.10.10.1,1,0x00,64,8,0,0x00,102,84,20
CNTR,10.10.12.1,5,6,10000000,1,3,848,8,0,4294967295,0,0,4294967295,0,\
0,4294967295,4294967295,0,0,0
    """
    result = parse_sflowtool(raw)

    expected = {
        'flow_count': 1,
        'sample_count': 1,
        'packets': [
            {
                'icmp_code': '0',
                'src_mac': '0a5e44a7e381',
                'packet_type': 'FLOW',
                'in_port': '424',
                'tcp_flags': '0x00',
                'icmp_type': '8',
                'src_ip': '10.10.10.2',
                'ip_ttl': '64',
                'out_port': '1073741823',
                'packet_size': '102',
                'ip_protocol': '1',
                'dst_ip': '10.10.10.1',
                'ip_size': '84',
                'eth_type': '0x0800',
                'in_vlan': '0',
                'agent_address': '10.10.12.1',
                'out_vlan': '0',
                'sampling_rate': '20',
                'dst_mac': '7072cfa36a9a',
                'ip_tos': '0x00'
            },
            {
                'if_type': '6',
                'in_ucastPkts': '8',
                'in_unknownProtos': '4294967295',
                'packet_type': 'CNTR',
                'if_direction': '1',
                'in_errors': '0',
                'in_mcastPkts': '0',
                'if_speed': '10000000',
                'out_octets': '0',
                'out_discards': '0',
                'if_promiscuousMode': '0',
                'in_discards': '0',
                'out_mcastPkts': '4294967295',
                'out_errors': '0',
                'if_index': '5',
                'in_bcastPkts': '4294967295',
                'out_ucastPkts': '0',
                'out_bcastPkts': '4294967295',
                'if_status': '3',
                'agent_address': '10.10.12.1',
                'in_octets': '848'
            }
        ]
    }

    dic_diff = DeepDiff(result, expected)
    assert not dic_diff
