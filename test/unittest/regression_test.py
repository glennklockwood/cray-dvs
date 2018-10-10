#!/usr/bin/python

"""
Copyright 2016 Cray Inc. All Rights Reserved.

This file is part of Cray Data Virtualization Service (DVS).

DVS is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

DVS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, see <http://www.gnu.org/licenses/>.
"""

"""Commentary
"""
import os
import re
import shlex
import subprocess
import time
import unittest
import json

class TestBaseClass(unittest.TestCase):
    """Base class for all of the tests below."""

    def setUp(self):
        pass

    def tearDown(self):
        pass


class Test00Format(TestBaseClass):

    def test_00_testformat(self):
        """Bootstrap testing"""

        # Brief, raw
        with open("/proc/fs/dvs/stats", "w") as fd:
            fd.writelines("enable,json,brief,raw,test")
        with open("/proc/fs/dvs/stats", "r") as fd:
            jdict = json.loads(fd.read())
        assert len(jdict) == 1              # single object
        assert 'container' in jdict
        jcont = jdict['container']
        assert 'nevervisible' not in jcont  # should never appear
        assert 'invisible' not in jcont     # should never appear in brief
        assert 'invisible1' not in jcont    # should never appear in brief
        # Brief, pretty
        with open("/proc/fs/dvs/stats", "w") as fd:
            fd.writelines("enable,json,brief,pretty,test")
        with open("/proc/fs/dvs/stats", "r") as fd:
            jdict2 = json.loads(fd.read())
        assert jdict == jdict2              # should be identical
        # Verbose, raw
        with open("/proc/fs/dvs/stats", "w") as fd:
            fd.writelines("enable,json,verbose,raw,test")
        with open("/proc/fs/dvs/stats", "r") as fd:
            jdict3 = json.loads(fd.read())
        assert jdict != jdict3              # should have extra lines
        assert 'container' in jdict3
        jcont = jdict3['container']
        assert 'nevervisible' not in jcont  # should never appear
        assert 'invisible' in jcont         # should appear in verbose
        assert 'invisible1' in jcont        # should appear in verbose
        # Verbose, pretty
        with open("/proc/fs/dvs/stats", "w") as fd:
            fd.writelines("enable,json,verbose,pretty,test")
        with open("/proc/fs/dvs/stats", "r") as fd:
            jdict4 = json.loads(fd.read())
        assert jdict3 == jdict4             # should be identical

    def test_01_output(self):
        """Basic test of statistics output"""

        # Test permutations of brief/verbose, pretty/raw
        for e in ['enable', 'disable']:
            for v in ['brief', 'verbose']:
                for p in ['pretty', 'raw']:
                    ops = ['json', 'notest', v, p, e]
                    with open("/proc/fs/dvs/stats", "w") as fd:
                        fd.writelines(','.join(ops))
                    with open("/proc/fs/dvs/stats", "r") as fd:
                        jdict = json.loads(fd.read())
                    assert 'STATS' in jdict
                    # Should ALWAYS see a version
                    assert 'version' in jdict['STATS']
                    # Should ALWAY see flags that match settings
                    assert 'flags' in jdict['STATS']
                    ops = jdict['STATS']['flags'].split(',')
                    assert 'json' in ops
                    assert 'notest' in ops
                    assert v in ops
                    assert p in ops
                    if (e == 'disable'):
                        assert len(jdict) == 1
        # Test basic stats categories
        with open("/proc/fs/dvs/stats", "w") as fd:
            fd.writelines('enable,json,verbose,raw,notest')
        with open("/proc/fs/dvs/stats", "r") as fd:
            jdict = json.loads(fd.read())
        assert 'STATS' in jdict
        assert 'IPC' in jdict
        assert 'RQ' in jdict
        assert 'OP' in jdict
        assert 'PERF' in jdict

if __name__ == "__main__":
    unittest.main()
