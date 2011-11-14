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
#!/usr/bin/env python

import socket
from threading import Thread
from Queue import Queue


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
    result_format = '   {0:<35} => {1:<35}'
    print''

    for target in args_target_list:
        valid_target = None
        try: # Extract port if one was specified
            host = (target.split(':'))[0]
            temp_port = (target.split(':'))[1]

        except IndexError: # No port was specified, default to 443
            port = 443
            valid_target = (host, port)

        else: # Make sure the provided port is an int
            try:
                port = int(temp_port)
            except ValueError: # Provided port is not an int
                print result_format.format(host + ':' + str(temp_port), \
                    'WARNING: Not a valid port, discarding corresponding tasks.')
            else:
                valid_target = (host, port)

        if valid_target: # Host and port are correct, let's try to connect
            worker = Thread(target=_test_connect,\
                             args=(valid_target, result_queue, socket_timeout))
            worker.start()
            thread_list.append(worker)

    # Grab each result and fill the task queue so that processes can start working
    alive_target_list = []
    for i in range(len(thread_list)):
        (host_addr, ip_addr, error_string) = result_queue.get()
        (host,port) = host_addr

        if ip_addr is None:
            print result_format.format(host + ':' + str(port), error_string)
        else:
            (ip, port) = ip_addr
            print result_format.format(host + ':' + str(port), ip + ':' + str(port))
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


def _test_connect(target, out_q, timeout):
    """
    Try to connect to the given target=(host,port) and put the result in out_q.
    """
    (host,port) = target
    s = socket.socket()
    s.settimeout(timeout)
    error_text = "N/A"
    ip_addr = None

    try:
        s.connect((host, port))
        # Host is up => keep the IP adress we actually connected to
        ip_addr = s.getpeername()

    except socket.timeout: # Host is down
        error_text = 'WARNING: Could not connect (timeout), discarding corresponding tasks.'
    except socket.gaierror: # Host is down
        error_text = 'WARNING: Could not connect, discarding corresponding tasks.'
    except socket.error: # Connection Refused
        error_text = 'WARNING: Connection rejected, discarding corresponding tasks.'

    finally:
        s.close()
        out_q.put( (target, ip_addr, error_text) )

    return
