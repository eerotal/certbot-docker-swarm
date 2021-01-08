"""Unit tests for SwarmInstallerUtils."""

import unittest
import time

from docker.models.secrets import Secret
from certbot_docker_swarm._internal.utils import SwarmInstallerUtils

class TestSwarmInstallerUtils(unittest.TestCase):
    def setUp(self):
        self.a = Secret()
        self.a.attrs = {"Spec": {"Labels": {}}}
        self.a.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_MANAGED] = "false"
        self.a.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_DOMAIN] = "1.example.com"
        self.a.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_NAME] = "cert"
        self.a.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_VERSION] = "0"
        self.a.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_FINGERPRINT] = "AA:BB"

        self.b = Secret()
        self.b.attrs = {"Spec": {"Labels": {}}}
        self.b.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_MANAGED] = "true"
        self.b.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_DOMAIN] = "2.example.com"
        self.b.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_NAME] = "cert"
        self.b.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_VERSION] = "1"
        self.b.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_FINGERPRINT] = "AA:CC"

        self.c = Secret()
        self.c.attrs = {"Spec": {"Labels": {}}}
        self.c.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_MANAGED] = "true"
        self.c.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_DOMAIN] = "2.example.com"
        self.c.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_NAME] = "chain"
        self.c.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_VERSION] = "2"
        self.c.attrs["Spec"]["Labels"][SwarmInstallerUtils.L_FINGERPRINT] = "AA:DD"

        self.d = Secret()
        self.d.attrs = {"Spec": {"Labels": {}}}

    def test_get_secret_managed(self):
        # Case 1
        self.assertFalse(SwarmInstallerUtils.get_secret_managed(self.a))

        # Case 2
        self.assertTrue(SwarmInstallerUtils.get_secret_managed(self.b))

        # Case 3
        self.assertTrue(SwarmInstallerUtils.get_secret_managed(self.c))

        # Case 4
        self.assertFalse(SwarmInstallerUtils.get_secret_managed(self.d))

    def test_get_secret_domain(self):
        # Case 1
        self.assertEqual(SwarmInstallerUtils.get_secret_domain(self.a), "1.example.com")

        # Case 2
        self.assertEqual(SwarmInstallerUtils.get_secret_domain(self.b), "2.example.com")

        # Case 3
        self.assertEqual(SwarmInstallerUtils.get_secret_domain(self.c), "2.example.com")

        # Case 4
        self.assertEqual(SwarmInstallerUtils.get_secret_domain(self.d), None)

    def test_get_secret_name(self):
        # Case 1
        self.assertEqual(SwarmInstallerUtils.get_secret_name(self.a), "cert")

        # Case 2
        self.assertEqual(SwarmInstallerUtils.get_secret_name(self.b), "cert")

        # Case 3
        self.assertEqual(SwarmInstallerUtils.get_secret_name(self.c), "chain")

        # Case 4
        self.assertEqual(SwarmInstallerUtils.get_secret_name(self.d), None)

    def test_get_secret_domain(self):
        # Case 1
        self.assertEqual(SwarmInstallerUtils.get_secret_version(self.a), "0")

        # Case 2
        self.assertEqual(SwarmInstallerUtils.get_secret_version(self.b), "1")

        # Case 3
        self.assertEqual(SwarmInstallerUtils.get_secret_version(self.c), "2")

        # Case 4
        self.assertEqual(SwarmInstallerUtils.get_secret_version(self.d), None)

    def test_get_secret_fingerprint(self):
        # Case 1
        self.assertEqual(SwarmInstallerUtils.get_secret_fingerprint(self.a), "AA:BB")

        # Case 2
        self.assertEqual(SwarmInstallerUtils.get_secret_fingerprint(self.b), "AA:CC")

        # Case 3
        self.assertEqual(SwarmInstallerUtils.get_secret_fingerprint(self.c), "AA:DD")

        # Case 4
        self.assertEqual(SwarmInstallerUtils.get_secret_fingerprint(self.d), None)

    def test_get_x509_fingerprint(self):
        pass

    def test_filter_secrets(self):
        secrets = [self.a, self.b, self.c]

        f = {}

        # Case 1
        f[SwarmInstallerUtils.L_MANAGED] = lambda x: x == "true"
        f[SwarmInstallerUtils.L_DOMAIN] = lambda x: x == "2.example.com"
        filtered = SwarmInstallerUtils.filter_secrets(secrets, f)
        self.assertEqual(len(filtered), 2)
        self.assertEqual(filtered[0], self.b)
        self.assertEqual(filtered[1], self.c)

        # Case 2
        f[SwarmInstallerUtils.L_NAME] = lambda x: x == "chain"
        filtered = SwarmInstallerUtils.filter_secrets(secrets, f)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0], self.c)

        # Case 3
        f[SwarmInstallerUtils.L_NAME] = lambda x: x == "fullchain"
        filtered = SwarmInstallerUtils.filter_secrets(secrets, f)
        self.assertEqual(len(filtered), 0)

    def test_sort_secrets(self):
        secrets = [self.a, self.b, self.c]

        # Case 1
        res = SwarmInstallerUtils.sort_secrets(
            secrets,
            SwarmInstallerUtils.L_VERSION,
            reverse=False,
            default=None
        )
        self.assertEqual(res[0], self.a)
        self.assertEqual(res[1], self.b)
        self.assertEqual(res[2], self.c)

    def test_sort_secrets_reverse(self):
        secrets = [self.a, self.b, self.c]

        # Case 1
        res = SwarmInstallerUtils.sort_secrets(
            secrets,
            SwarmInstallerUtils.L_VERSION,
            reverse=True ,
            default=None
        )
        self.assertEqual(res[2], self.a)
        self.assertEqual(res[1], self.b)
        self.assertEqual(res[0], self.c)

    def test_sort_secrets_different_default(self):
        secrets = [self.a, self.b, self.c, self.d]

        # Case 1
        res = SwarmInstallerUtils.sort_secrets(
            secrets,
            SwarmInstallerUtils.L_VERSION,
            reverse=True,
            default="100"
        )
        self.assertEqual(res[0], self.a)
        self.assertEqual(res[1], self.b)
        self.assertEqual(res[2], self.c)
        self.assertEqual(res[3], self.d)

        # Case 2
        res = SwarmInstallerUtils.sort_secrets(
            secrets,
            SwarmInstallerUtils.L_VERSION,
            reverse=True,
            default="-1"
        )
        self.assertEqual(res[0], self.d)
        self.assertEqual(res[1], self.a)
        self.assertEqual(res[2], self.b)
        self.assertEqual(res[3], self.c)

if __name__ == "__main__":
    unittest.main()
