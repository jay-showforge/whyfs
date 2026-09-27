"""fentry (BPF trampoline) detection must not inherit BCC 0.29's x86_64-only check.

BCC's BPF.support_kfunc() returns False on every non-x86_64 machine, although arm64
kernels (6.0+) have BPF trampolines and BCC's attach path is architecture-neutral.  On the
Ubuntu 24.04 arm64 kernel this made whyfs refuse to start at all.
"""
import contextlib
import sys
import types
import unittest
from unittest import mock

from whyfs.ebpf_bcc import kfunc_supported


def fake_bpf(bcc_says, symbols):
    class BPF:
        @staticmethod
        def support_kfunc():
            return bcc_says

        @staticmethod
        def ksymname(name):
            return 0xffff0000 if name in symbols else -1
    return BPF


class KfuncDetectionTests(unittest.TestCase):
    def _with_btf(self, btf):
        lib = types.SimpleNamespace(bpf_has_kernel_btf=lambda: btf)
        libbcc = types.ModuleType("bcc.libbcc")
        libbcc.lib = lib
        pkg = sys.modules.get("bcc") or types.ModuleType("bcc")
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.dict(sys.modules, {"bcc": pkg, "bcc.libbcc": libbcc}))
        stack.enter_context(mock.patch.object(pkg, "libbcc", libbcc, create=True))  # real bcc: attribute wins
        return stack

    def test_bcc_yes_is_yes(self):
        self.assertTrue(kfunc_supported(fake_bpf(True, set())))

    def test_arm64_kernel_with_trampolines_is_supported(self):
        with self._with_btf(True):
            self.assertTrue(kfunc_supported(fake_bpf(False, {"bpf_trampoline_link_prog", "arch_prepare_bpf_trampoline"})))

    def test_no_arch_trampoline_is_unsupported(self):
        with self._with_btf(True):
            self.assertFalse(kfunc_supported(fake_bpf(False, {"bpf_trampoline_link_prog"})))

    def test_no_btf_is_unsupported(self):
        with self._with_btf(False):
            self.assertFalse(kfunc_supported(fake_bpf(False, {"bpf_trampoline_link_prog", "arch_prepare_bpf_trampoline"})))


if __name__ == "__main__":
    unittest.main()
