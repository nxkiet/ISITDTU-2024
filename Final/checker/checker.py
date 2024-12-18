#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import copy
import base64
import string 

from checklib import *

argv = copy.deepcopy(sys.argv)

from drink import *

class Checker(BaseChecker):
    vulns: int = 1
    timeout: int = 10
    uses_attack_data: bool = False

    def __init__(self, *args, **kwargs):
        super(Checker, self).__init__(*args, **kwargs)
        self.mch = CheckMachine(self)

    def action(self, action, *args, **kwargs):
        try:
            super(Checker, self).action(action, *args, **kwargs)
        except pwnlib.exception.PwnlibException:
            self.cquit(Status.DOWN, 'Connection error', 'Got requests connection error')
    
    def check(self):
        sth = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))
        sth = base64.b64encode(sth.encode()).decode()

        with self.mch.connection() as io:
            user1, pass1, description1 = rnd_username(), rnd_password(), rnd_string(30)

            self.mch.register(io, user1, pass1, description1,  Status.MUMBLE)
            # login
            self.mch.login(io, user1, pass1, Status.MUMBLE)

            # check rule function
            self.mch.Check_SeaDrink(io, sth, Status.MUMBLE)
            self.mch.quit(io, "2")
            self.mch.quit(io, "3")

        self.cquit(Status.OK)

    def put(self, flag_id: str, flag: str):
        with self.mch.connection() as io:
            username, password = rnd_username(), rnd_password() 

            self.mch.register(io, username, password, flag, Status.MUMBLE)
            self.mch.login(io, username, password, Status.MUMBLE)
    
            self.mch.quit(io, "2")
            self.mch.quit(io, "3")
            
        # self.cquit(Status.OK)
        self.cquit(Status.OK, f'{username}:{password}',f'{username}:{password}')

    def get(self, flag_id: str, flag: str):
        with self.mch.connection() as io:
            username, password = flag_id.split(':')
            self.mch.login(io, username, password, Status.CORRUPT)
            value = self.mch.showflag(io)[8:]
            self.mch.quit(io, "2")
            self.mch.quit(io, "3")

            self.assert_eq(value, flag.encode(), "Flag invalid", Status.CORRUPT)
            
        self.cquit(Status.OK)

if __name__ == '__main__':
    c = Checker(argv[2])

    try:
        c.action(argv[1], *argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)