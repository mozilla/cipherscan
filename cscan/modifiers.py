# Copyright (c) 2016 Hubert Kario
# Released under Mozilla Public License 2.0

"""Methods for modifying the scan configurations on the fly."""

from __future__ import print_function

proto_versions = {(3, 0): "SSLv3",
                  (3, 1): "TLSv1.0",
                  (3, 2): "TLSv1.1",
                  (3, 3): "TLSv1.2",
                  (3, 4): "TLSv1.3",
                  (3, 5): "TLSv1.4",
                  (3, 6): "TLSv1.5"}


def version_to_str(version):
    """Convert a version tuple to human-readable string."""
    version_name = proto_versions.get(version, None)
    if version_name is None:
        version_name = "{0[0]}.{0[1]}".format(version)
    return version_name


def set_hello_version(generator, version):
    """Set client hello version."""
    generator.version = version
    generator.modifications += [version_to_str(version)]
    return generator
