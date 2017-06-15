# AIRNET PROJECT
# Copyright (c) 2017 Messaoud AOUADJ, Emmanuel LAVINAL, Mayoro BADJI

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
