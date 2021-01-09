import setuptools

with open("README.md", "r") as f:
    long_desc = f.read()

setuptools.setup(
    name="certbot-docker-swarm",
    version="0.0.1",
    author="Eero Talus",
    author_email="eerotal@mbnet.fi",
    description="Certbot Docker Swarm installer plugin",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    url="https://github.com/eerotal/certbot-docker-swarm",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD 3-clause license",
        "Operating System :: OS Independent",
    ],
    python_requires='>=2.7',
    install_requires=[
        "docker>=4.2",
        "certbot>=1.4",
        "pyOpenSSL>=19.1"
    ],
    entry_points={
        "certbot.plugins": [
            'docker-swarm = certbot_docker_swarm._internal.installer:SwarmInstaller'
        ]
    }
)
