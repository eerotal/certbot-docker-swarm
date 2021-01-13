"""Unit tests for SwarmInstallerUtils."""

import pytest
import time
import os

from docker.models.secrets import Secret
from certbot_docker_swarm._internal.utils import SwarmInstallerUtils as utils


class TestSwarmInstallerUtils:
    @pytest.fixture
    def secrets(self):
        a = Secret()
        a.attrs = {"Spec": {"Labels": {}}}
        a.attrs["Spec"]["Name"] = "a"
        a.attrs["Spec"]["Labels"][utils.L_MANAGED] = "false"
        a.attrs["Spec"]["Labels"][utils.L_DOMAIN] = "1.example.com"
        a.attrs["Spec"]["Labels"][utils.L_NAME] = "cert"
        a.attrs["Spec"]["Labels"][utils.L_VERSION] = "0"
        a.attrs["Spec"]["Labels"][utils.L_FINGERPRINT] = "AA:BB"

        b = Secret()
        b.attrs = {"Spec": {"Labels": {}}}
        b.attrs["Spec"]["Name"] = "b"
        b.attrs["Spec"]["Labels"][utils.L_MANAGED] = "true"
        b.attrs["Spec"]["Labels"][utils.L_DOMAIN] = "2.example.com"
        b.attrs["Spec"]["Labels"][utils.L_NAME] = "chain"
        b.attrs["Spec"]["Labels"][utils.L_VERSION] = "1"
        b.attrs["Spec"]["Labels"][utils.L_FINGERPRINT] = "AA:CC"

        c = Secret()
        c.attrs = {"Spec": {"Labels": {}}}
        c.attrs["Spec"]["Name"] = "c"
        c.attrs["Spec"]["Labels"][utils.L_MANAGED] = "true"
        c.attrs["Spec"]["Labels"][utils.L_DOMAIN] = "2.example.com"
        c.attrs["Spec"]["Labels"][utils.L_NAME] = "chain"
        c.attrs["Spec"]["Labels"][utils.L_VERSION] = "2"
        c.attrs["Spec"]["Labels"][utils.L_FINGERPRINT] = "AA:DD"

        d = Secret()
        d.attrs = {"Spec": {"Labels": {}}}
        d.attrs["Spec"]["Name"] = "d"

        return {"a": a, "b": b, "c": c, "d": d}

    def test_get_secret_managed(self, secrets):
        a, b, c, d = [secrets[x] for x in sorted(secrets)]

        assert utils.get_secret_managed(a) is False
        assert utils.get_secret_managed(b) is True
        assert utils.get_secret_managed(c) is True
        assert utils.get_secret_managed(d) is False

    def test_get_secret_domain(self, secrets):
        a, b, c, d = [secrets[x] for x in sorted(secrets)]

        assert utils.get_secret_domain(a) == "1.example.com"
        assert utils.get_secret_domain(b) == "2.example.com"
        assert utils.get_secret_domain(c) == "2.example.com"
        assert utils.get_secret_domain(d) is None

    def test_get_secret_name(self, secrets):
        a, b, c, d = [secrets[x] for x in sorted(secrets)]

        assert utils.get_secret_name(a) == "cert"
        assert utils.get_secret_name(b) == "chain"
        assert utils.get_secret_name(c) == "chain"
        assert utils.get_secret_name(d) is None

    def test_get_secret_domain(self, secrets):
        a, b, c, d = [secrets[x] for x in sorted(secrets)]

        assert utils.get_secret_version(a) == "0"
        assert utils.get_secret_version(b) == "1"
        assert utils.get_secret_version(c) == "2"
        assert utils.get_secret_version(d) is None

    def test_get_secret_fingerprint(self, secrets):
        a, b, c, d = [secrets[x] for x in sorted(secrets)]

        assert utils.get_secret_fingerprint(a) == "AA:BB"
        assert utils.get_secret_fingerprint(b) == "AA:CC"
        assert utils.get_secret_fingerprint(c) == "AA:DD"
        assert utils.get_secret_fingerprint(d) is None

    def test_get_x509_fingerprint(self):
        fingerprint = ("D7:5C:60:9E:BE:8F:78:67:1D:0E:16:98:80:96:3A:B5:"
                       "FF:88:A7:94:19:75:6D:11:A0:3E:1F:33:21:90:54:7F")

        assert utils.get_x509_fingerprint(
            os.path.dirname(__file__) + "/assets/cert.pem"
        ) == fingerprint

    def test_filter_secrets(self, secrets):
        a, b, c, d = [secrets[x] for x in sorted(secrets)]

        f = {}
        filtered = utils.filter_secrets([a, b, c, d], f)
        assert filtered == []

        f[utils.L_MANAGED] = lambda x: x == "true"
        f[utils.L_DOMAIN] = lambda x: x == "2.example.com"
        filtered = utils.filter_secrets([a, b, c, d], f)
        assert filtered == [b, c]

        f[utils.L_MANAGED] = lambda x: x == "false"
        f[utils.L_DOMAIN] = lambda x: x == "1.example.com"
        f[utils.L_NAME] = lambda x: x == "cert"
        filtered = utils.filter_secrets([a, b, c, d], f)
        assert filtered == [a]

        f[utils.L_NAME] = lambda x: x == "fullchain"
        filtered = utils.filter_secrets([a, b, c, d], f)
        assert filtered == []

    def test_sort_secrets(self, secrets):
        a, b, c, d = [secrets[x] for x in sorted(secrets)]

        res = utils.sort_secrets(
            [a, b, c],
            utils.L_VERSION,
            reverse=False,
            default=None
        )
        assert res == [a, b, c]

    def test_sort_secrets_reverse(self, secrets):
        a, b, c, d = [secrets[x] for x in sorted(secrets)]

        # Case 1
        res = utils.sort_secrets(
            [a, b, c],
            utils.L_VERSION,
            reverse=True,
            default=None
        )
        assert res == [c, b, a]

    def test_sort_secrets_different_default(self, secrets):
        a, b, c, d = [secrets[x] for x in sorted(secrets)]

        res = utils.sort_secrets(
            [a, b, c, d],
            utils.L_VERSION,
            reverse=True,
            default="100"
        )
        assert res == [a, b, c, d]

        res = utils.sort_secrets(
            [a, b, c, d],
            utils.L_VERSION,
            reverse=True,
            default="-1"
        )
        assert res == [d, a, b, c]

    def test_secret_renews(self, secrets):
        a, b, c, d = [secrets[x] for x in sorted(secrets)]

        assert utils.secret_renews(a, b) is False
        assert utils.secret_renews(a, c) is False
        assert utils.secret_renews(a, d) is False
        assert utils.secret_renews(b, a) is False
        assert utils.secret_renews(b, c) is True
        assert utils.secret_renews(b, d) is False
        assert utils.secret_renews(c, a) is False
        assert utils.secret_renews(c, b) is False
        assert utils.secret_renews(c, d) is False
        assert utils.secret_renews(d, a) is False
        assert utils.secret_renews(d, b) is False
        assert utils.secret_renews(d, c) is False
