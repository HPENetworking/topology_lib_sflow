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
topology_lib_sflow communication library implementation.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from topology.libraries.utils import stateprovider

from .parser import parse_pid, parse_sflowtool


path = "/tmp"


class SflowtoolState(object):
    """
    State object for sflowtool.

    :param int pid: Process id of the running sFlow collector (sflowtool).
    """
    def __init__(self, sflowtool_pid=None):
        self.sflowtool_pid = sflowtool_pid


@stateprovider(SflowtoolState)
def sflowtool_start(enode, state, mode, port=6343):
    """
    Start sflowtool

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :param str mode: sflowtool mode (detail/line)
    :param int port: sflowtool port to listen on.
    """
    assert mode is "detail" or mode is "line"

    if mode is "detail":
        cmd = [
            "sflowtool -p {port}".format(port=port)
        ]
    else:
        cmd = [
            "sflowtool -l -p {port}".format(port=port)
        ]

    cmd.append("2>&1 > {path}/sflowtool.log &".format(path=path))

    state.sflowtool_pid = parse_pid(enode(' '.join(cmd), shell='bash'))


@stateprovider(SflowtoolState)
def sflowtool_stop(enode, state):
    """
    Stop sflowtool

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :return: A dictionary as returned by \
        :func:`topology_lib_sflow.parser.parse_sflowtool`
    """

    enode("kill {pid}".format(pid=state.sflowtool_pid), shell="bash")

    state.sflowtool_pid = None

    return parse_sflowtool(
        enode("cat {path}/sflowtool.log".format(path=path), shell="bash")
    )


def check_ping_sample(enode, sflow_output, host1, host2, agent_address):
    """
    Parse sflowtool output to look for a specific ping request and
    ping response between two hosts.

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :param str sflow_output: dict of parsed sflowtool output
    :param str host1: IP address of host which sends the ping rquest
    :param str host2: IP address of host which sends the ping response
    :param str agent_address: sFlow agent IP address
    :return bool result: A boolean value to indicate presence of ping packets
                         in sFlow samples (Both request and response)
    """

    assert sflow_output
    assert host1, host2
    assert agent_address

    ping_request = False
    ping_response = False

    for packet in sflow_output['packets']:
        if ping_request is False and \
                packet['packet_type'] == 'FLOW' and \
                packet['ip_protocol'] == '1' and \
                int(packet['icmp_type']) == 8 and \
                packet['src_ip'] == host1 and \
                packet['dst_ip'] == host2:
            ping_request = True
            assert packet['agent_address'] == agent_address
        if ping_response is False and \
                packet['packet_type'] == 'FLOW' and \
                packet['ip_protocol'] == '1' and \
                int(packet['icmp_type']) == 0 and \
                packet['src_ip'] == host2 and \
                packet['dst_ip'] == host1:
            ping_response = True
            assert packet['agent_address'] == agent_address
        if ping_request and ping_response:
            break

    result = ping_request and ping_response
    return result


__all__ = [
    'sflowtool_start',
    'sflowtool_stop',
    'check_ping_sample'
]
