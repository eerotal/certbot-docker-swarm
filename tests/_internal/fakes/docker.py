from docker.models.nodes import Node
from docker.models.secrets import Secret
from docker.models.services import Service


class NodeCollectionDefs:
    @classmethod
    def list(cls):
        return [
            Node(attrs={
                "ID": "abcde",
                "Spec": {
                    "Role": "manager"
                }
            })
        ]

    @classmethod
    def get(cls, node_id):
        for n in cls.list():
            if n.id == node_id:
                return n

    @classmethod
    def get_not_manager(cls, node_id):
        tmp = cls.get(node_id)
        tmp.attrs["Spec"]["Role"] = "node"
        return tmp


class SecretCollectionDefs:
    @classmethod
    def list(cls):
        ret = []

        return [
            Secret(attrs={
                'ID': 'a',
                'Spec': {
                    'Name': '1.example.com_cert_v0',
                    'Labels': {
                        'certbot.certificate-fingerprint': 'AA:BB',
                        'certbot.domain': '1.example.com',
                        'certbot.managed': 'true',
                        'certbot.name': 'cert',
                        'certbot.version': '0'
                    }
                }
            }),
            Secret(attrs={
                'ID': 'b',
                'Spec': {
                    'Name': '1.example.com_chain_v0',
                    'Labels': {
                        'certbot.certificate-fingerprint': 'AA:BB',
                        'certbot.domain': '1.example.com',
                        'certbot.managed': 'true',
                        'certbot.name': 'chain',
                        'certbot.version': '0'
                    }
                }
            }),
            Secret(attrs={
                'ID': 'c',
                'Spec': {
                    'Name': '2.example.com_cert_v0',
                    'Labels': {
                        'certbot.certificate-fingerprint': 'AA:BB',
                        'certbot.domain': '2.example.com',
                        'certbot.managed': 'true',
                        'certbot.name': 'cert',
                        'certbot.version': '0'
                    }
                }
            }),
            Secret(attrs={
                'ID': 'd',
                'Spec': {
                    'Name': '2.example.com_chain_v0',
                    'Labels': {
                        'certbot.certificate-fingerprint': 'AA:BB',
                        'certbot.domain': '2.example.com',
                        'certbot.managed': 'true',
                        'certbot.name': 'chain',
                        'certbot.version': '0'
                    }
                }
            }),
            Secret(attrs={
                'ID': 'e',
                'Spec': {
                    'Name': '2.example.com_cert_v1',
                    'Labels': {
                        'certbot.certificate-fingerprint': 'AA:BB',
                        'certbot.domain': '2.example.com',
                        'certbot.managed': 'true',
                        'certbot.name': 'cert',
                        'certbot.version': '1'
                    }
                }
            }),
            Secret(attrs={
                'ID': 'f',
                'Spec': {
                    'Name': '2.example.com_chain_v1',
                    'Labels': {
                        'certbot.certificate-fingerprint': 'AA:BB',
                        'certbot.domain': '2.example.com',
                        'certbot.managed': 'true',
                        'certbot.name': 'chain',
                        'certbot.version': '1'
                    }
                }
            })
        ]

    @classmethod
    def get(cls, secret_id):
        for s in cls.list():
            if s.id == secret_id:
                return s


class ServiceCollectionDefs:
    @classmethod
    def list(cls):
        return [
            Service(attrs={
                "ID": "qwerty",
                "Spec": {
                    "Name": "Test Service",
                    "TaskTemplate": {
                        "ContainerSpec": {
                            "Secrets": [
                                {
                                    "SecretID": "c",
                                    "SecretName": "example.com_cert_v0",
                                    "File": {
                                        "Name": "example.com_cert",
                                        "UID": "0",
                                        "GID": "0",
                                        "Mode": "292"
                                    }
                                },
                                {
                                    "SecretID": "d",
                                    "SecretName": "example.com_chain_v0",
                                    "File": {
                                        "Name": "example.com_chain",
                                        "UID": "0",
                                        "GID": "0",
                                        "Mode": "292"
                                    }
                                }
                            ]
                        }
                    }
                }
            })
        ]

    @classmethod
    def list_no_secrets(cls):
        services = cls.list()
        for service in services:
            del service.attrs["Spec"]["TaskTemplate"] \
                             ["ContainerSpec"]["Secrets"]

        return services

    @classmethod
    def get(cls, service_id):
        for service in cls.list():
            if service.id == service_id:
                return service


class DockerClientDefs:
    @classmethod
    def info(cls, *args, **kwargs):
        return {
            "Swarm": {
                "NodeID": "abcde",
                "LocalNodeState": "active",
                "Cluster": {
                    "Spec": {
                        "Orchestration": {
                            "TaskHistoryRetentionLimit": 5
                        }
                    }
                }
            }
        }

    @classmethod
    def info_not_swarm(cls, *args, **kwargs):
        tmp = cls.info()
        tmp["Swarm"]["LocalNodeState"] = "inactive"
        return tmp
