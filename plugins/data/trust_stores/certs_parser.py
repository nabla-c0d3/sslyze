#!/usr/bin/env python

from sys import argv


certs_input = open(argv[1], 'r')
certs_output = open('{}.new'.format(argv[1]), 'wa')

cert_head = 'BEGIN CERTIFICATE'
cert_tail = 'END CERTIFICATE'
cert_line = False

for line in certs_input:
    if (line.find(cert_head) > 0) or (line.find(cert_tail) > 0):
        certs_output.write(line)
        cert_line = not cert_line
    elif cert_line:
        certs_output.write(line)
