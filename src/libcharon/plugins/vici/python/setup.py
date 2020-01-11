from setuptools import setup

with open('README.rst') as file:
    long_description = file.read()

setup(
    name="vici",
    version="@EGG_VERSION@",
    description="Native Python interface for strongSwan's VICI protocol",
    long_description=long_description,
    author="strongSwan Project",
    author_email="info@strongswan.org",
    url="https://wiki.strongswan.org/projects/strongswan/wiki/Vici",
    license="MIT",
    packages=["vici"],
    include_package_data=True,
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    classifiers=(
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    )
)
