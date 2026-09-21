#!/usr/bin/env python3

# Copyright 2026 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Minimal UDP DNS responder for egress smoke tests.

Answers every question with a single A record (192.0.2.1), which is enough
for the dnsproxy health probe (default root IN NS only checks for a response)
and for dig A queries. Usage: blackhole_upstream.py <ip> <port>.
"""

import socket
import struct
import sys


def build_response(query):
    if len(query) < 12:
        return b""
    tid, _flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", query[:12])
    offset = 12
    for _ in range(qd):
        while offset < len(query) and query[offset] != 0:
            offset += 1 + query[offset]
        offset += 1 + 4
    question = query[12:offset]
    header = struct.pack("!HHHHHH", tid, 0x8180, qd, qd, 0, 0)
    answer = b""
    if qd:
        rdata = socket.inet_aton("192.0.2.1")
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, len(rdata)) + rdata
    return header + question + answer


def main():
    ip, port = sys.argv[1], int(sys.argv[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    while True:
        data, peer = sock.recvfrom(4096)
        resp = build_response(data)
        if resp:
            sock.sendto(resp, peer)


if __name__ == "__main__":
    main()
