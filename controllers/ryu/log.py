# coding: utf8

# AirNet, a virtual network control language based on an Edge-Fabric model.
# Copyright (C) 2016-2017 Université Toulouse III - Paul Sabatier
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import os

class Logger :

    def __init__ (self, name, _file="messages.log") :
        self.Close(_file)
        self.logger = logging.getLogger(name)
        self.formatter = logging.Formatter('%(asctime)s : %(name)s : [%(levelname)s] : %(message)s')
        self.handler = logging.FileHandler(_file,mode="a", encoding="utf-8")
        self.handler.setFormatter(self.formatter)

    def Log(self, level="DEBUG") :
        if level.upper() == "INFO" :
            self.handler.setLevel(logging.INFO)
            self.logger.setLevel(logging.INFO)
        elif level.upper() == "WARNING" :
            self.handler.setLevel(logging.WARNING)
            self.logger.setLevel(logging.WARNING)
        elif level.upper() == "ERROR" :
            self.handler.setLevel(logging.ERROR)
            self.logger.setLevel(logging.ERROR)
        elif level.upper() == "CRITICAL" :
            self.handler.setLevel(logging.CRITICAL)
            self.logger.setLevel(logging.CRITICAL)
        else :
            self.handler.setLevel(logging.DEBUG)
            self.logger.setLevel(logging.DEBUG)

        self.logger.addHandler(self.handler)
        return self.logger

    def Close(self, _file):
        file_dsc = open(_file,'w')
        file_dsc.close()
