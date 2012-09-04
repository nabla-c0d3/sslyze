#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginBase.py
# Purpose:      Main abstract plugin class. All the plugins are
#               subclasses of PluginBase.
#
# Author:       aaron, alban
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

from utils.ctSSL import constants
from utils.HTTPSConnection import HTTPSConnection
from utils import STARTTLS


class AvailableCommands:
    """
    This object tells the main process which command line option(s)
    a plugin implements. Every plugin should have a class attribute called
    available_commands that is an instance of AvailableCommands.
    """

    def __init__(self, title, description):
        """
        Title and description are sent to optparse.OptionGroup().
        """
        self.title = title
        self.description = description
        self.options = []
        self.commands = []

    def add_option(self, option, help, dest):
        """
        Options are settings specific to one single plugin. 
        They are sent to PluginBase._shared_settings.
        """
        self.options.append( (option, help, dest) )
        
    def add_command(self, command, help, dest):
        """
        Commands are actions/scans the plugin implements, with 
        PluginXXX.process_task().
        Command and help are sent to optparse.OptionGroup.add_option().
        Note: dest to None if you don't need arguments
        """
        self.commands.append( (command, help, dest) )


class PluginResult:
    """
    Plugin.process_task() should return an instance of this class.
    """    
    def __init__(self, text_result, xml_result):
        """
        @type text_result: [str]
        @param text_result: Printable version of the plugin's results.
        Each string within the list gets printed as a separate line.
        
        @type xml_result: xml.etree.ElementTree.Element
        @param xml_result: XML version of the plugin's results.
        """            
        self._text_result = text_result
        self._xml_result = xml_result

    def get_xml_result(self):
        return self._xml_result
        
    def get_txt_result(self):  
        return self._text_result  



class PluginBase(object):
    """
    Base plugin abstract class. All plugins have to inherit from it.
    """
    __metaclass__ = abc.ABCMeta
    
    # _shared_settings contains read-only info available to all the plugins: 
    # client certificate, timeoutvalue, etc...
    # TODO: Document it
    _shared_settings = None
    
    # Formatting stuff
    PLUGIN_TITLE_FORMAT = '  * {0} :'
    
                              
    @classmethod
    def get_commands(plugin_class):
        """
        This method returns the AvailableCommands object for the current plugin.
        """
        return plugin_class.available_commands

    @abc.abstractmethod
    def process_task(self, target, command, args):
        """
        This method should implement what the plugin is expected to do / test
        when given a target=(host, ip_addr, port), a command line option, and
        a command line argument. It has to be defined in each plugin class.
        """
        return

