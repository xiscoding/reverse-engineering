#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIMPLE EXPLORATION 
find a state that reaches a certain address, while discarding all states that go through another address
Simulation manager has a shortcut for this pattern, the .explore() method

Created on Sun Mar 31 12:48:01 2024

@author: xdoestech
"""
import angr

proj = angr.Project("/home/xdoestech/Desktop/reverse_engineering/myFirst_crackme/first_crack")
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"YAY: you win!" in s.posix.dumps(1))

s = simgr.found[0]
print(s.posix.dumps(1))

flag = s.posix.dumps(0)
print(flag)


