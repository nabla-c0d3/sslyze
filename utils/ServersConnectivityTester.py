#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         ServersConnectivityTester.py
# Purpose:      Sanitizes a list of servers and tests connectivity to each 
#               server.
#
# Author:       alban
#
# Copyright:    2012 SSLyze developers
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

import abc
import socket
from ThreadPool import ThreadPool


class InvalidTargetError(Exception):
        
    RESULT_FORMAT = '\n   {0:<35} => WARNING: {1}; discarding corresponding tasks.'
    
    def __init__(self, target_str, error_msg):
        self._target_str = target_str
        self._error_msg = error_msg
        
    def get_error_msg(self):
        return self.RESULT_FORMAT.format(self._target_str, self._error_msg )


class ConnectivityTester(object):
    """
    Unneeded abstract class to clarify how ProxyConnectivityTester and 
    ServersConnectivityTester work.
    """
    __metaclass__ = abc.ABCMeta
    
    HOST_FORMAT = '{0[0]}:{0[2]}'
    IP_FORMAT = '{0[1]}:{0[2]}'

    @abc.abstractmethod
    def __init__(self, target_list, proxy_str):
        return
        
    @abc.abstractmethod
    def test_connectivity(self, timeout):
        return
    
    @abc.abstractmethod
    def get_result_str(self):
        return


class ProxyConnectivityTester(ConnectivityTester):
    """
    Tests connectivity to the proxy specified with --https_tunnel.
    Connectivity to the actual targets is not verified.
    """
        
    ERR_PROXY_OFFLINE = ('\n   {0:<35} => ERROR: Could not connect to the '
                         'proxy; discarding all tasks.')
    PROXY_OK_FORMAT = '\n   {0:<35}  => {1} - Proxy OK'
    
    def __init__(self, target_list, proxy_str):
        
        self._target_list = target_list
        self._proxy_str = proxy_str
        self._result_str = ''
    
    
    def test_connectivity(self, timeout):
        """
        Tests connectivity with the proxy and returns the list of valid 
        host:port strings within the target list.
        """

        # If a proxy was specified, we only test connectivity with the proxy
        try:
            proxy_test = SSLServerTester(self._proxy_str)
            proxy = proxy_test.test_connectivity(timeout)
            self._result_str += self.PROXY_OK_FORMAT.format(self.HOST_FORMAT.format(proxy),
                                                       self.IP_FORMAT.format(proxy))
            
        except InvalidTargetError as e: # Stop right away if the proxy is offline
            self._result_str += self.ERR_PROXY_OFFLINE.format(self._proxy_str)
            return
        
        # Then parse the host:port strings but don't try to connect
        for target_str in self._target_list:
            try:
                test_target = SSLServerTester(target_str)
                target = test_target.get_target()
                yield target
            except InvalidTargetError as e:
                self._result_str += e.get_error_msg()
                        
        return
    
    
    def get_result_str(self):
        return self._result_str     


class ServersConnectivityTester(ConnectivityTester):
    """
    Tests connectivity to a list of servers.
    """
    
    MAX_THREADS = 10

    TARGET_OK_FORMAT = '\n   {0:<35} => {1}'

    def __init__(self, target_list, starttls=None, xmpp_to=None):
        
        self._target_list = target_list
        self._starttls = starttls
        self._xmpp_to = xmpp_to
        self._targets_OK = []
        self._targets_ERR = []

   
    def test_connectivity(self,  timeout):
        """
        Tests connectivity with each server of the target_list and returns 
        the list of online servers.
        """
        
        # Use a thread pool to connect to each server
        thread_pool = ThreadPool()
        for target_str in self._target_list:
            thread_pool.add_job((self._test_server,
                                (target_str, timeout)))
            
        nb_threads = min(len(self._target_list), self.MAX_THREADS)
        thread_pool.start(nb_threads)
        
        # Recover valid targets
        for (job, target) in thread_pool.get_result():
            self._targets_OK.append(target)
            yield target
                        
        # Store invvalid targets
        for (job, exception) in thread_pool.get_error():
            self._targets_ERR.append(exception)

        thread_pool.join()
        return   


    def get_result_str(self):
        result_str = ''
        for target in self._targets_OK:
            result_str += self.TARGET_OK_FORMAT.format(self.HOST_FORMAT.format(target),
                                                       self.IP_FORMAT.format(target))

        for exception in self._targets_ERR:
            print exception
            result_str += exception.get_error_msg()

        return result_str    
          
 
    def _test_server(self, target, timeout):
        
        if self._starttls == 'smtp':
            server_test = SMTPServerTester(target)
        elif self._starttls == 'xmpp':
            server_test = XMPPServerTester(target, self._xmpp_to)
        else:
            server_test = SSLServerTester(target)
            
        return server_test.test_connectivity(timeout)


class SSLServerTester(object):
    """
    Checks to see if a given server is accessible/online. The constructor parses 
    the host:port string (and can fail). Then, test_connectivity() can be used 
    to check if the server is online.
    """
    
    ERR_BAD_PORT = 'Not a valid host:port'
    ERR_TIMEOUT = 'Could not connect (timeout)'
    ERR_NAME_NOT_RESOLVED = 'Could not resolve hostname'
    ERR_REJECTED = 'Connection rejected'
    
    DEFAULT_PORT = 443
    
    
    def __init__(self, target_str):
        
        # Parse target string
        if ':' in target_str:
            host = (target_str.split(':'))[0]
            try:
                port = int((target_str.split(':'))[1])
            except: # Port is not an int
                raise InvalidTargetError(target_str, self.ERR_BAD_PORT)
        else:
            host = target_str
            port = self.DEFAULT_PORT
            
        self._target_str = host + ':' + str(port)
        self._target = (host, host, port)
        

    def get_target(self):
        return self._target
        

    def test_connectivity(self, timeout):
        """
        Tries to connect to the given target=(host,port).
        """
        (host, ip_addr, port) = self._target
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((ip_addr, port))
            ip_addr = s.getpeername()[0]
            self._connect_callback(s) # StartTLS callback
    
        except socket.timeout: # Host is down
            raise InvalidTargetError(self._target_str, self.ERR_TIMEOUT)
        except socket.error: # Connection Refused
            raise InvalidTargetError(self._target_str, self.ERR_REJECTED)
        except socket.gaierror:
            raise InvalidTargetError(self._target_str,
                                     self.ERR_NAME_NOT_RESOLVED)
    
        finally:
            s.close()
    
        return (host, ip_addr, port)
    
    
    def _connect_callback(self, socket):
        pass
        
        
class SMTPServerTester(SSLServerTester):
    """
    Tests connectivity and STARTTLS support with an SMTP server.
    """
    
    ERR_SMTP_REJECTED = 'SMTP EHLO was rejected'
    ERR_NO_SMTP_STARTTLS = 'SMTP STARTTLS not supported'
    
    DEFAULT_PORT = 25
    
    def __init__(self, target):
        
        super(SMTPServerTester, self).__init__(target)
    
    
    def _connect_callback(self, s):
        """
        Using a socket already connected to an SMTP server, tries to initiate a 
        STARTLS handshake.
        """
        # Send a EHLO and wait for the 250 status
        s.recv(2048)
        s.send('EHLO sslyze.scan\r\n')
        if '250 ' not in s.recv(2048):
            raise InvalidTargetError(self._target_str, self.ERR_SMTP_REJECTED)
                
        # Semd a STARTTLS
        s.send('STARTTLS\r\n')
        smtp_resp = s.recv(2048)
        if 'Ready to start TLS'  not in smtp_resp:
            raise InvalidTargetError(self._target_str,self.ERR_NO_SMTP_STARTTLS)


class XMPPServerTester(SSLServerTester):
    """
    Tests connectivity and STARTTLS support with an XMPP server.
    """
    
    ERR_XMPP_REJECTED = 'Error opening XMPP stream, try --xmpp_to'
    ERR_NO_XMPP_STARTTLS = 'XMPP STARTTLS not supported'
    
    XMPP_OPEN_STREAM = ("<stream:stream xmlns='jabber:client' xmlns:stream='"
        "http://etherx.jabber.org/streams' xmlns:tls='http://www.ietf.org/rfc/"
        "rfc2595.txt' to='{0}'>" )
    XMPP_STARTTLS = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    
    DEFAULT_PORT = 5222
    
    def __init__(self, target, xmpp_to=None):
        
        super(XMPPServerTester, self).__init__(target)
        self._xmpp_to = xmpp_to
        if xmpp_to == None: # Default to hostname for xmpp_to
            self._xmpp_to = self._target[0]
        
    
    def _connect_callback(self, s):
        """
        Using a socket already connected to an XMPP server, tries to initiate a 
        STARTLS handshake.
        """
        # Open an XMPP stream
        s.send(self.XMPP_OPEN_STREAM.format(self._xmpp_to))
        if '<stream:error>' in s.recv(2048):
            raise InvalidTargetError(self._target_str, self.ERR_XMPP_REJECTED)
            
        # Send a STARTTLS
        s.send(self.XMPP_STARTTLS)
        if 'proceed'  not in s.recv(2048): 
            raise InvalidTargetError(self._target_str,self.ERR_NO_XMPP_STARTTLS)


