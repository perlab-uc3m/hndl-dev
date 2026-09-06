import signal
import unittest

from capture.common import CaptureLifecycle


class FakeProcess:
    def __init__(self):
        self.returncode = None
        self.signals = []
        self.terminated = False

    def poll(self):
        return self.returncode

    def send_signal(self, value):
        self.signals.append(value)

    def wait(self, timeout=None):
        self.returncode = 0
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def kill(self):
        self.returncode = -signal.SIGKILL


class FakeThread:
    def __init__(self):
        self.joined = False

    def join(self, timeout=None):
        self.joined = True


class CaptureLifecycleTests(unittest.TestCase):
    def test_registered_capture_is_stopped_after_failure(self):
        process = FakeProcess()
        thread = FakeThread()
        with self.assertRaisesRegex(ValueError, "injected client failure"):
            with CaptureLifecycle() as lifecycle:
                lifecycle.register(process, (thread,))
                raise ValueError("injected client failure")
        self.assertEqual(process.signals, [signal.SIGINT])
        self.assertTrue(thread.joined)
        self.assertEqual(process.returncode, 0)

    def test_registered_server_is_terminated_after_failure(self):
        process = FakeProcess()
        with self.assertRaisesRegex(RuntimeError, "injected parser failure"):
            with CaptureLifecycle() as lifecycle:
                lifecycle.register_process(process, "test server")
                raise RuntimeError("injected parser failure")
        self.assertTrue(process.terminated)


if __name__ == "__main__":
    unittest.main()
