import sqlite3
import unittest
from unittest.mock import MagicMock

from lib.attacks.find import SCCMHUNTER


class FakeEntry:
    """Minimal stand-in for an ldap3 Entry -- dict-style access, but not a
    plain str/dict, so passing one straight into a sqlite bind parameter
    fails exactly like issue #97's 'Error binding parameter 1: type Entry
    is not supported'."""

    def __init__(self, attrs):
        self._attrs = attrs

    def __contains__(self, key):
        return key in self._attrs

    def __getitem__(self, key):
        return self._attrs[key]


def _make_sccmhunter():
    hunter = SCCMHUNTER.__new__(SCCMHUNTER)
    hunter.conn = sqlite3.connect(":memory:")
    hunter.conn.executescript(
        """
        CREATE TABLE Groups(cn, name, sAMAAccontName, member, description);
        CREATE TABLE Users(cn, name, sAMAAccontName, servicePrincipalName, description);
        CREATE TABLE Computers(Hostname, SiteCode, SigningStatus, SiteServer, ManagementPoint, DistributionPoint, WSUS, MSSQL);
        """
    )
    return hunter


class ResolvedGroupMemberComputerTests(unittest.TestCase):
    """Issue #97: with -resolve, a nested group member that's a computer was
    passed to add_computer_to_db() as the raw ldap3 Entry instead of its
    hostname string, crashing sqlite with
    "Error binding parameter 1: type 'Entry' is not supported"."""

    def setUp(self):
        self.hunter = _make_sccmhunter()
        self.hunter.resolve = True

        group_entry = FakeEntry({
            "sAMAccountType": 268435456,
            "cn": "SCCM Admins",
            "name": "SCCM Admins",
            "sAMAccountName": "SCCM Admins",
            "member": "",
            "description": "",
            "distinguishedname": "CN=SCCM Admins,DC=example,DC=test",
        })
        self.hunter.ldap_session = MagicMock()
        self.hunter.ldap_session.entries = [group_entry]

        resolved_computer = FakeEntry({
            "sAMAccountType": 805306369,
            "dNSHostname": "dp01.example.test",
        })
        self.hunter.recursive_resolution = MagicMock(return_value=[resolved_computer])

    def test_resolved_computer_member_is_stored_by_hostname_string(self):
        self.hunter.check_strings()

        rows = self.hunter.conn.execute("SELECT Hostname FROM Computers").fetchall()
        self.assertEqual(rows, [("dp01.example.test",)])


if __name__ == "__main__":
    unittest.main()
