"""

helper which exposes the https://attrs.org library and some
type validation helpers.

"""
import attr  # noqa
import six
from attr import attrs, attrib  # noqa
from attr import validators as v


def attrib_float():
    return attrib(validator=v.instance_of(float))


def attrib_text():
    return attrib(validator=v.instance_of(six.text_type))


def attrib_bytes():
    return attrib(validator=v.instance_of(bytes), converter=str2bytes)


def attrib_text_or_none():
    return attrib(validator=v.optional(v.instance_of(six.text_type)),
                  default=None)


def attrib_bytes_or_none():
    return attrib(validator=v.optional(v.instance_of(bytes)),
                  default=None, converter=str2bytes)


def str2bytes(x):
    if x is not None and not isinstance(x, bytes):
        return x.encode("ascii")
    return x
