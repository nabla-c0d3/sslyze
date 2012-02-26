#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         discover_targets.py
# Purpose:      Tries to connect to a list of servers and returns the list of
#               servers that actually responded.
#
# Author:       aaron, alban
#
# Copyright:    2011 SSLyze developers (http://code.google.com/sslyze)
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

import socket
from threading import Thread
from Queue import Queue

RESULT_FORMAT = '   {0:<35} => {1:<35}'

def is_target_valid(target, default_port = 443):
    valid_target = None
    
    try: # Extract port if one was specified
        host = (target.split(':'))[0]
        temp_port = (target.split(':'))[1]
    
    except IndexError: # No port was specified, use default
        port = default_port
        valid_target = (host, port)
    
    else: # Make sure the provided port is an int
        port = int(temp_port)
        valid_target = (host, port)
        
    return valid_target

    

def discover_targets(args_target_list, args_command_list, available_commands, main_task_queue):
    """
    Gets a list of strings "host:port", discards hosts that are not responding
    to a TCP connection attempt, and fills the main_task_queue with the work
    to do, defined by args_command_list.
    """
    # Create thread pool. One thread per valid target
    result_queue = Queue()
    thread_list = []
    socket_timeout = args_command_list.timeout
    alive_target_list = []
    print''
    
    # If an HTTP CONNECT proxy was specified, we only make sure that the proxy 
    # is alive.
    if args_command_list.https_tunnel:
        (host,port) = is_target_valid(args_command_list.https_tunnel)
        
        if _test_connect((host,port), socket_timeout) is None: 
            print RESULT_FORMAT.format(
                args_command_list.https_tunnel, 
                'ERROR: Could not connect to proxy, discarding all tasks.')
            
        else: # Proxy is alive
            print RESULT_FORMAT.format(
                args_command_list.https_tunnel, 
                'Proxy OK')
            
            for target in args_target_list:
                try:
                    (host,port) = is_target_valid(target)
                except:
                    print RESULT_FORMAT.format(target, \
                        'WARNING: Not a valid host/port, discarding corresponding tasks.')
                
                else: # Don't try to connect
                    target = (host, host, port)
                    alive_target_list.append(target)
                    # Fill the task queue if target is up
                    for command in available_commands:
                        if getattr(args_command_list, command):
                            args = args_command_list.__dict__[command]
                            main_task_queue.put( (target, command, args) )
            
            
    # No proxy try to connect to all targets
    else:  
        if args_command_list.starttls == 'smtp':
            default_port = 25
            test_stattls = test_starttls_smtp
            test_starttls_args = ()
        elif args_command_list.starttls == 'xmpp':
            default_port = 5222
            test_stattls = test_starttls_xmpp
            test_starttls_args = args_command_list.xmpp_to
        else:
            default_port = 443
            test_stattls = None
            test_starttls_args = ()
            
        for target in args_target_list:
            try:
                (host,port) = is_target_valid(target, default_port)
            except:
                print RESULT_FORMAT.format(target, \
                    'WARNING: Not a valid host/port'
                    ', discarding corresponding tasks.')
            
            else: # Host and port are correct, let's try to connect
                worker = \
                    Thread(target=_test_connect, 
                           args=(
                                 (host,port), 
                                 socket_timeout, 
                                 result_queue, 
                                 test_stattls,
                                 test_starttls_args))
                worker.start()
                thread_list.append(worker)
    
        # Grab each result and fill the task queue so that processes can start working
        for i in xrange(len(thread_list)):
            (host_addr, ip_addr, error_string) = result_queue.get()
            (host,port) = host_addr
    
            if error_string is not '': # An error occurred
                print RESULT_FORMAT.format(host + ':' + str(port), error_string)
            else:
                (ip, port) = ip_addr
                print RESULT_FORMAT.format(host + ':' + str(port), ip + ':' + str(port))
                target = (host, ip, port) # Keep the IP address we found
                alive_target_list.append(target)
                # Fill the task queue if target is up
                for command in available_commands:
                    if getattr(args_command_list, command):
                        args = args_command_list.__dict__[command]
                        main_task_queue.put( (target, command, args) )
    
            result_queue.task_done()
    
        # Make sure all the worker threads had time to terminate
        [worker.join() for worker in thread_list]
        result_queue.join()

    return alive_target_list


def _test_connect(target, timeout, out_q=None, test_starttls=None, test_starttls_args=()):
    """
    Try to connect to the given target=(host,port) and put the result in out_q.
    """
    (host,port) = target
    s = socket.socket()
    s.settimeout(timeout)
    error_text = ''
    ip_addr = None

    try:
        s.connect((host, port))
        # Host is up => keep the IP address we actually connected to
        ip_addr = s.getpeername()
        if test_starttls:
            error_text = test_starttls(s, host, test_starttls_args)

    except socket.timeout: # Host is down
        error_text = 'WARNING: Could not connect (timeout), discarding corresponding tasks.'
    except socket.gaierror: # Host is down
        error_text = 'WARNING: Could not connect, discarding corresponding tasks.'
    except socket.error: # Connection Refused
        error_text = 'WARNING: Connection rejected, discarding corresponding tasks.'

    finally:
        s.close()
        if out_q:
            out_q.put( (target, ip_addr, error_text) )

    return ip_addr


def test_starttls_smtp(s, host): 
    """
    Using a socket already connected to an SMTP server, try to initiate a 
    STARTLS handshake.
    """
    error_text = ''
    # Send a EHLO and wait for the 250 status
    s.recv(2048)
    s.send('EHLO sslyze.scan\r\n')
    if '250 ' not in s.recv(2048):
        return 'WARNING: SMTP EHLO was rejected, discarding corresponding tasks.'
            
    # Semd a STARTTLS
    s.send('STARTTLS\r\n')
    smtp_resp = s.recv(2048)
    if 'Ready to start TLS'  not in smtp_resp:
        error_text = 'WARNING: SMTP STARTTLS not supported, discarding corresponding tasks.'
        
    return error_text


def test_starttls_xmpp(sock, host, xmpp_to): 
    """
    Using a socket already connected to an XMPP server, try to initiate a 
    STARTLS handshake.
    """
    xmpp_open_stream = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' xmlns:tls='http://www.ietf.org/rfc/rfc2595.txt' to='{0}'>" 
    xmpp_starttls = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    
    if xmpp_to is None:
        xmpp_to = host
    
    error_text = ''
    # Open an XMPP stream
    sock.send(xmpp_open_stream.format(xmpp_to))
    if '<stream:error>' in sock.recv(2048):
        return 'WARNING: Error opening XMPP stream, discarding corresponding tasks. Consider using --xmpp_to ?'
        
    # Send a STARTTLS
    sock.send(xmpp_starttls)
    if 'proceed'  not in sock.recv(2048): 
        error_text = 'WARNING: XMPP STARTTLS not supported, discarding corresponding tasks.'
        
    return error_text
        

