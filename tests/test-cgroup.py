#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Integration tests for cgroup v2 CPU and memory limits.
#
# The tests are deliberately workload-based: they verify that the limits
# are observable from the sandbox and that CPU and memory intensive
# workloads are constrained without taking down the sandbox's main
# process.  Some CI environments only delegate cgroups to a transient
# systemd scope, so the launcher helper retries there when necessary.

import importlib.util
import os
import shutil
import subprocess
import tempfile
import time
import unittest


_spec = importlib.util.spec_from_file_location(
    'test_helper',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test-helper.py'),
)
_helper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helper)

BWRAP = _helper.BWRAP
can_run_bwrap = _helper.can_run_bwrap
run_tap_tests = _helper.run_tap_tests

BASE_BWRAP_ARGS = ['--ro-bind', '/', '/', '--dev', '/dev',
                   '--proc', '/proc', '--tmpfs', '/tmp']

CPU_WORKLOAD = r'''
import resource
import time

start = time.monotonic()
while time.monotonic() - start < 2.0:
    pass

usage = resource.getrusage(resource.RUSAGE_SELF)
print("CPU_SECONDS=%.3f" % (usage.ru_utime + usage.ru_stime))
'''

MEMORY_WORKLOAD = r'''
import sys

size = 128 * 1024 * 1024
try:
    data = bytearray(size)
    for offset in range(0, size, 4096):
        data[offset] = 1
    print("MEMORY_ALLOCATED")
except MemoryError:
    print("MEMORY_ERROR")
'''

_cgroup_error_markers = (
    'cgroup',
    'Cgroup',
    'CPU and memory limits require',
    'Permission denied',
)


def _looks_like_cgroup_setup_failure(stderr):
    text = stderr.decode(errors='replace')
    return any(marker in text for marker in _cgroup_error_markers)


def _run_once(args, timeout=30):
    return subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def run_bwrap_with_cgroup(cgroup_args, command, timeout=30):
    """Run bwrap, retrying in a delegated systemd scope if necessary."""
    command = [BWRAP, *BASE_BWRAP_ARGS, *cgroup_args, '--', *command]
    result = _run_once(command, timeout=timeout)

    if result.returncode == 0 or not _looks_like_cgroup_setup_failure(result.stderr):
        return result

    systemd_run = shutil.which('systemd-run')
    if systemd_run is None:
        return result

    delegated = [
        systemd_run, '--user', '--scope', '-q', '-p', 'Delegate=yes',
        '--', *command,
    ]
    retried = _run_once(delegated, timeout=timeout)

    # If systemd-run itself could not start a scope, prefer the original
    # bwrap error: it is more useful in test diagnostics.
    if retried.returncode != 0 and b'Failed to' in retried.stderr:
        return result

    return retried


_cgroup_available = None


def cgroup_test_available():
    global _cgroup_available

    if _cgroup_available is not None:
        return _cgroup_available

    if not can_run_bwrap():
        _cgroup_available = False
        return _cgroup_available

    try:
        result = run_bwrap_with_cgroup(
            ['--cgroup-memory', '16M', '--cgroup-cpu', '0.5'],
            ['true'],
        )
        _cgroup_available = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        _cgroup_available = False

    return _cgroup_available


def parse_cpu_seconds(output):
    if isinstance(output, bytes):
        output = output.decode(errors='replace')
    values = []
    for line in output.splitlines():
        if line.startswith('CPU_SECONDS='):
            values.append(float(line.split('=', 1)[1]))
    return values


@unittest.skipUnless(can_run_bwrap(), 'bwrap not available or not functional')
@unittest.skipUnless(cgroup_test_available(), 'cgroup v2 is not delegated')
class TestCgroupLimits(unittest.TestCase):
    def assert_succeeded(self, result):
        self.assertEqual(
            result.returncode, 0,
            f'bwrap failed with {result.returncode}:\n'
            f'stdout={result.stdout.decode(errors="replace")}\n'
            f'stderr={result.stderr.decode(errors="replace")}',
        )

    def test_cpu_limit_is_effective(self):
        result = run_bwrap_with_cgroup(
            ['--cgroup-cpu', '0.5'],
            ['python3', '-c', CPU_WORKLOAD],
        )
        self.assert_succeeded(result)

        cpu_seconds = parse_cpu_seconds(result.stdout)
        self.assertEqual(len(cpu_seconds), 1, result.stdout)
        # 2 seconds of wall time at 50% CPU is about 1 second of CPU.
        self.assertLess(cpu_seconds[0], 1.6, result.stdout)
        self.assertGreater(cpu_seconds[0], 0.2, result.stdout)

    def test_memory_limit_is_effective_without_ooming_container(self):
        script = (
            'python3 -c "$1"; '
            'status=$?; '
            'echo WORKLOAD_STATUS=$status; '
            'base=/sys/fs/cgroup; '
            'cg=$(sed -n "s/^0:://p" /proc/self/cgroup); '
            'echo MEMORY_MAX=$(cat "$base$cg/memory.max"); '
            'echo MAIN_ALIVE'
        )

        result = run_bwrap_with_cgroup(
            ['--cgroup-memory', '32M'],
            ['sh', '-c', script, 'sh', MEMORY_WORKLOAD],
        )
        self.assert_succeeded(result)

        output = result.stdout.decode(errors='replace')
        self.assertIn('MEMORY_MAX=33554432', output)
        self.assertIn('MAIN_ALIVE', output)
        self.assertNotIn('MEMORY_ALLOCATED', output)
        if 'MEMORY_ERROR' not in output:
            self.assertRegex(output, r'WORKLOAD_STATUS=(137|139)')

    def test_mixed_workloads_share_limits_and_container_survives(self):
        script = (
            'python3 -c "$1" & cpu1=$!; '
            'python3 -c "$1" & cpu2=$!; '
            'python3 -c "$2" & mem=$!; '
            'wait "$mem" || true; '
            'wait "$cpu1" || true; '
            'wait "$cpu2" || true; '
            'base=/sys/fs/cgroup; '
            'cg=$(sed -n "s/^0:://p" /proc/self/cgroup); '
            'echo CPU_MAX=$(cat "$base$cg/cpu.max"); '
            'echo MAIN_ALIVE'
        )

        result = run_bwrap_with_cgroup(
            ['--cgroup-cpu', '0.5', '--cgroup-memory', '48M'],
            ['sh', '-c', script, 'sh', CPU_WORKLOAD, MEMORY_WORKLOAD],
        )
        self.assert_succeeded(result)

        output = result.stdout.decode(errors='replace')
        self.assertIn('CPU_MAX=50000 100000', output)
        self.assertIn('MAIN_ALIVE', output)

        cpu_seconds = parse_cpu_seconds(result.stdout)
        self.assertEqual(len(cpu_seconds), 2, output)
        # Two CPU hogs for 2 seconds would use about 4 CPU-seconds without
        # a limit.  The shared 50% limit allows about 1 CPU-second.
        self.assertLess(sum(cpu_seconds), 1.8, output)

    def test_limits_work_with_unshared_namespaces(self):
        result = run_bwrap_with_cgroup(
            ['--unshare-all', '--cgroup-cpu', '0.5', '--cgroup-memory', '32M'],
            [
                'sh', '-c',
                'sed -n "s/^0:://p" /proc/self/cgroup; '
                'python3 -c "$1"; '
                'echo NAMESPACE_OK',
                'sh', CPU_WORKLOAD,
            ],
        )
        self.assert_succeeded(result)

        output = result.stdout.decode(errors='replace')
        self.assertIn('/', output.splitlines())
        self.assertIn('NAMESPACE_OK', output)
        cpu_seconds = parse_cpu_seconds(output)
        self.assertEqual(len(cpu_seconds), 1, output)
        self.assertLess(cpu_seconds[0], 1.6, output)

        result = run_bwrap_with_cgroup(
            ['--unshare-user', '--unshare-pid', '--unshare-cgroup',
             '--cgroup-memory', '32M'],
            ['sh', '-c', 'sed -n "s/^0:://p" /proc/self/cgroup; '
                         'echo CGROUP_NS_OK'],
        )
        self.assert_succeeded(result)
        output = result.stdout.decode(errors='replace')
        self.assertIn('/', output.splitlines())
        self.assertIn('CGROUP_NS_OK', output)

    def test_cgroup_is_removed_after_sandbox_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, 'cgroup.txt')
            result = run_bwrap_with_cgroup(
                ['--bind', tmp, tmp, '--setenv', 'OUT', out,
                 '--cgroup-memory', '32M'],
                ['sh', '-c', 'sed -n "s/^0:://p" /proc/self/cgroup > "$OUT"'],
            )
            self.assert_succeeded(result)

            with open(out) as f:
                cgroup_path = f.read().strip()
            self.assertTrue(cgroup_path.startswith('/'), cgroup_path)

            host_path = '/sys/fs/cgroup' + cgroup_path
            deadline = time.monotonic() + 5
            while os.path.exists(host_path) and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertFalse(os.path.exists(host_path),
                             f'{host_path} was not cleaned up')

    def test_invalid_limits_are_rejected(self):
        for args in (
            ['--cgroup-memory', 'not-a-size'],
            ['--cgroup-memory', '0'],
            ['--cgroup-cpu', '0'],
            ['--cgroup-cpu', 'not-a-cpu-limit'],
        ):
            result = _run_once([BWRAP, *args, 'true'], timeout=10)
            self.assertNotEqual(result.returncode, 0, args)
            self.assertTrue(result.stderr, args)


if __name__ == '__main__':
    run_tap_tests(__import__('__main__'))
