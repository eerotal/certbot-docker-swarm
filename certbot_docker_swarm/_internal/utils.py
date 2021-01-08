"""Utility class for SwarmInstaller."""

import OpenSSL

class SwarmInstallerUtils:
    SECRET_FORMAT="{domain}_{name}_v{version}"

    L_PREFIX = "certbot"
    L_MANAGED = L_PREFIX + ".managed"
    L_VERSION = L_PREFIX + ".version"
    L_DOMAIN = L_PREFIX + ".domain"
    L_NAME = L_PREFIX + ".name"
    L_FINGERPRINT = L_PREFIX + ".certificate-fingerprint"

    @classmethod
    def get_secret_managed(cls, s):
        # type: (Secret) -> bool
        """Get the value of the 'managed' secret label."""
        value = s.attrs.get("Spec").get("Labels").get(cls.L_MANAGED, False)
        return value == "true"

    @classmethod
    def get_secret_domain(cls, s):
        # type: (Secret) -> str
        """Get the value of the 'domain' secret label."""
        return s.attrs.get("Spec").get("Labels").get(cls.L_DOMAIN, None)

    @classmethod
    def get_secret_name(cls, s):
        # type: (Secret) -> bool
        """Get the value of the 'name' secret label."""
        return s.attrs.get("Spec").get("Labels").get(cls.L_NAME, None)

    @classmethod
    def get_secret_version(cls, s):
        # type: (Secret) -> str
        """Get the value of the 'version' secret label."""
        return s.attrs.get("Spec").get("Labels").get(cls.L_VERSION, None)

    @classmethod
    def get_secret_fingerprint(cls, s):
        # type: (Secret) -> str
        """Get the value of the 'fingerprint' secret label."""
        return s.attrs.get("Spec").get("Labels").get(cls.L_FINGERPRINT, None)

    @classmethod
    def get_x509_fingerprint(cls, cert_path):
        # type: (str) -> str
        """Get a SHA256 fingerprint of a certificate file.

        :param str cert_path: The path to the x509 certificate fil.

        :return: The SHA256 digest of the certificate.
        :rtype: str
        """

        with open(cert_path, "rb") as f:
            cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM,
                f.read()
            )
            return cert.digest("sha256").decode("utf-8")

    @classmethod
    def filter_secrets(cls, secrets, filter_dict):
        # type (List[Secrets], dict)
        """Filter a list of secrets based on label values.

        :param List[Secret] secrets: A list of Secrets to filter.
        :param dict filter_dict: A dictionary of label name -> function
                                 associations. The functions are passed
                                 the label value as the only argument and
                                 the functions should return true if the
                                 label value is correct.

        :return: A filtered list of Secrets.
        :rtype: List[Secret]
        """

        def filter_func(x):
            for label_name in filter_dict:
                label_value = x.attrs \
                               .get("Spec") \
                               .get("Labels") \
                               .get(label_name, None)
                if not filter_dict[label_name](label_value):
                    return False
            return True

        return list(filter(filter_func, secrets))

    @classmethod
    def sort_secrets(cls, secrets, label, reverse=False, default=None):
        """Sort a list of secrets based on the value of a label.

        :param List[Secret] secrets: A list of Secrets to sort.
        :param str label: The name of the label to use for sorting.
        :param bool reverse: Sort the list in reverse order.
        :param Any default: The default value to use if the label doesn't exist.

        :return: A sorted list of Secrets.
        :rtype: List[Secret]
        """

        return sorted(
            secrets,
            key=lambda x: x.attrs.get("Spec").get("Labels").get(label, default),
            reverse=reverse
        )

    @classmethod
    def secret_renews(cls, old, new):
        # type: (Secret, Secret) -> bool
        """Check whether a Secret renews another Secret."""

        return cls.get_secret_managed(old) and \
               cls.get_secret_managed(new) and \
               cls.get_secret_domain(old) == cls.get_secret_domain(new) and \
               cls.get_secret_name(old) == cls.get_secret_name(new)
