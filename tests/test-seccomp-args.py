#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import errno
import logging
import os
import subprocess
import sys
import termios
import unittest


TIOCSTI = getattr(termios, 'TIOCSTI', None)
TIOCNOTTY = getattr(termios, 'TIOCNOTTY', None)


class Test(unittest.TestCase):
    def setUp(self) -> None:
        here = os.path.dirname(os.path.abspath(__file__))

        if 'G_TEST_SRCDIR' in os.environ:
            self.test_srcdir = os.getenv('G_TEST_SRCDIR') + '/tests'
        else:
            self.test_srcdir = here

        if 'G_TEST_BUILDDIR' in os.environ:
            self.test_builddir = os.getenv('G_TEST_BUILDDIR') + '/tests'
        else:
            self.test_builddir = here

        self.bwrap = os.getenv('BWRAP', 'bwrap')
        self.try_syscall = os.path.join(self.test_builddir, 'try-syscall')

        if TIOCSTI is None or TIOCNOTTY is None:
            self.skipTest('TIOCSTI/TIOCNOTTY are not available')

        completed = subprocess.run(
            [
                self.bwrap,
                '--ro-bind', '/', '/',
                'true',
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=2,
        )

        if completed.returncode != 0:
            raise unittest.SkipTest(
                'cannot run bwrap (does it need to be setuid?)'
            )

    def run_syscall(self, syscall, *options):
        return subprocess.run(
            [
                self.bwrap,
                '--ro-bind', '/', '/',
                *options,
                self.try_syscall, syscall,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

    def assert_syscall_errno(self, syscall, expected, *options):
        completed = self.run_syscall(syscall, *options)
        self.assertEqual(
            completed.returncode,
            expected,
            completed.stderr.decode(errors='replace'),
        )

    def test_argument_eq(self) -> None:
        rule = 'errno:ECONNREFUSED ioctl arg1 == 0x{:x}'.format(TIOCSTI)

        self.assert_syscall_errno(
            'ioctl TIOCSTI', errno.ECONNREFUSED,
            '--seccomp-rule', rule,
        )
        self.assert_syscall_errno(
            'ioctl TIOCNOTTY', errno.EBADF,
            '--seccomp-rule', rule,
        )

    def test_argument_masked_eq(self) -> None:
        rule = 'errno:ECONNREFUSED ioctl arg1 & 0xffffffff == TIOCSTI'

        self.assert_syscall_errno(
            'ioctl TIOCSTI', errno.ECONNREFUSED,
            '--seccomp-rule', rule,
        )

        completed = self.run_syscall(
            'ioctl TIOCSTI CVE-2019-10063',
            '--seccomp-rule', rule,
        )
        if completed.returncode == errno.ENOENT:
            print('# Cannot test 64-bit syscall parameter on 32-bit')
        else:
            self.assertEqual(
                completed.returncode,
                errno.ECONNREFUSED,
                completed.stderr.decode(errors='replace'),
            )

        self.assert_syscall_errno(
            'ioctl TIOCNOTTY', errno.EBADF,
            '--seccomp-rule', rule,
        )

    def test_argument_ne(self) -> None:
        rule = 'errno:ECONNREFUSED ioctl arg1 != TIOCNOTTY'

        self.assert_syscall_errno(
            'ioctl TIOCSTI', errno.ECONNREFUSED,
            '--seccomp-rule', rule,
        )
        self.assert_syscall_errno(
            'ioctl TIOCNOTTY', errno.EBADF,
            '--seccomp-rule', rule,
        )

    def test_multiple_rules_and_arguments(self) -> None:
        self.assert_syscall_errno(
            'ioctl TIOCSTI', errno.ECONNREFUSED,
            '--seccomp-rule', 'allow ioctl arg1 == TIOCNOTTY',
            '--seccomp-rule',
            'errno:ECONNREFUSED ioctl '
            'arg0 == 0xffffffff arg1 == TIOCSTI',
        )
        self.assert_syscall_errno(
            'ioctl TIOCNOTTY', errno.EBADF,
            '--seccomp-rule', 'allow ioctl arg1 == TIOCNOTTY',
            '--seccomp-rule', 'errno:ECONNREFUSED ioctl arg1 == TIOCSTI',
        )

    def test_syscall_without_arguments(self) -> None:
        self.assert_syscall_errno(
            'listen', errno.ECONNREFUSED,
            '--seccomp-rule', 'errno:ECONNREFUSED listen',
        )
        self.assert_syscall_errno(
            'ioctl TIOCNOTTY', errno.EBADF,
            '--seccomp-rule', 'errno:ECONNREFUSED listen',
        )

    def test_namespace_combination(self) -> None:
        rule = 'errno:ECONNREFUSED ioctl arg1 == TIOCSTI'

        self.assert_syscall_errno(
            'ioctl TIOCSTI', errno.ECONNREFUSED,
            '--unshare-user-try',
            '--unshare-pid',
            '--unshare-ipc',
            '--unshare-uts',
            '--seccomp-rule', rule,
        )
        self.assert_syscall_errno(
            'ioctl TIOCNOTTY', errno.EBADF,
            '--unshare-user-try',
            '--unshare-pid',
            '--unshare-ipc',
            '--unshare-uts',
            '--seccomp-rule', rule,
        )

    def test_invalid_rules(self) -> None:
        invalid_rules = [
            'deny read',
            'errno:EPERM',
            'errno:EPERM not-a-syscall',
            'errno:EPERM ioctl arg6 == 0',
            'errno:EPERM ioctl arg0 = 0',
            'errno:EPERM ioctl arg0 & 0xff',
            'errno:EPERM ioctl arg0 & 0xff ~ 0',
        ]

        for rule in invalid_rules:
            with self.subTest(rule=rule):
                completed = subprocess.run(
                    [
                        self.bwrap,
                        '--ro-bind', '/', '/',
                        '--seccomp-rule', rule,
                        'true',
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(completed.returncode, 1)
                self.assertIn(b'bwrap: ', completed.stderr)

    def test_invalid_default_action(self) -> None:
        for action in ['deny', 'errno:99999']:
            with self.subTest(action=action):
                completed = subprocess.run(
                    [
                        self.bwrap,
                        '--ro-bind', '/', '/',
                        '--seccomp-default', action,
                        'true',
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(completed.returncode, 1)
                self.assertIn(b'bwrap: ', completed.stderr)


def main():
    logging.basicConfig(level=logging.DEBUG)

    try:
        from tap.runner import TAPTestRunner
    except ImportError:
        TAPTestRunner = None    # type: ignore

    if TAPTestRunner is not None:
        runner = TAPTestRunner()
        runner.set_stream(True)
        unittest.main(testRunner=runner)
    else:
        print('# tap.runner not available, using simple TAP output')
        print('1..1')
        program = unittest.main(exit=False)
        if program.result.wasSuccessful():
            print('ok 1 - %r' % program.result)
        else:
            print('not ok 1 - %r' % program.result)
            sys.exit(1)


if __name__ == '__main__':
    main()
