import socket
import unittest
from unittest.mock import MagicMock

from lib.attacks.smb import SMB


class SmbHunterFailureTests(unittest.TestCase):
    """Issue #106: a NETBIOS timeout (or any other mid-session failure) used
    to make smb_hunter() return None, which every caller unpacks into 7
    variables unconditionally -- crashing with
    'TypeError: cannot unpack non-iterable NoneType object'."""

    def setUp(self):
        self.smb = SMB.__new__(SMB)

    def _assert_safe_unknown_tuple(self, conn):
        result = self.smb.smb_hunter("dp01.example.test", conn)
        # Must always be unpackable into exactly 7 values -- this is what
        # every call site in check_siteservers/check_managementpoints/
        # check_distributionpoints/check_computers does unconditionally.
        signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe = result
        self.assertIsNone(signing)
        self.assertEqual(site_code, 'None')
        self.assertIsNone(siteserv)
        self.assertIsNone(distp)
        self.assertIsNone(wsus)
        self.assertIsNone(wdspxe)
        self.assertIsNone(sccmpxe)

    def test_netbios_timeout_does_not_crash_callers(self):
        conn = MagicMock()
        conn.isSigningRequired.side_effect = socket.timeout("The NETBIOS connection with the remote host timed out.")
        self._assert_safe_unknown_tuple(conn)

    def test_generic_socket_error_does_not_crash_callers(self):
        conn = MagicMock()
        conn.isSigningRequired.side_effect = socket.error("Connection reset by peer")
        self._assert_safe_unknown_tuple(conn)

    def test_unexpected_exception_does_not_crash_callers(self):
        conn = MagicMock()
        conn.listShares.side_effect = RuntimeError("something else entirely")
        conn.isSigningRequired.return_value = False
        self._assert_safe_unknown_tuple(conn)

    def test_successful_query_is_unaffected(self):
        conn = MagicMock()
        conn.isSigningRequired.return_value = True
        conn.listShares.return_value = []
        result = self.smb.smb_hunter("dp01.example.test", conn)
        signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe = result
        self.assertTrue(signing)
        self.assertEqual(site_code, 'None')
        self.assertFalse(siteserv)
        self.assertFalse(distp)
        self.assertFalse(wsus)
        self.assertFalse(wdspxe)
        self.assertFalse(sccmpxe)


if __name__ == "__main__":
    unittest.main()
