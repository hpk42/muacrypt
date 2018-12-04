# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals
import six
import pytest
from muacrypt import mime
from base64 import b64encode


def make_ac_dict(**kwargs):
    d = {}
    for name, val in kwargs.items():
        d[six.text_type(name)] = val
    d.setdefault("type", "1")
    d.setdefault("prefer-encrypt", "nopreference")
    return d


def test_parse_message_from_file(datadir):
    msg = mime.parse_message_from_file(datadir.open("rsa2048-simple.eml"))
    assert msg.get_all("Autocrypt")
    assert msg.get_payload()


def test_parse_message_from_string(datadir):
    msg = mime.parse_message_from_string(datadir.read("rsa2048-simple.eml"))
    assert msg.get_all("Autocrypt")
    assert msg.get_payload()


def test_render(datadir):
    msg = datadir.get_mime("rsa2048-simple.eml")
    x = mime.render_mime_structure(msg)
    assert "text/plain" in x


def test_render_filename_unicode(datadir):
    msg = datadir.get_mime("multipart_fn_unicode.eml")
    x = mime.render_mime_structure(msg)
    assert "rsicht" in x


def test_make_and_parse_header_value():
    addr, keydata = "x@xy.z", b64encode(b'123')
    h = mime.make_ac_header_value(addr=addr, keydata=keydata)
    r = mime.parse_ac_headervalue(h)
    assert not r.error
    assert r.keydata == keydata
    assert r.addr == addr
    assert not r.extra_attr


@pytest.mark.parametrize("addr", ["x@xy.z", "X@xY.z"])
def test_make_and_parse_header_value_with_full_addr(addr):
    addr, keydata = "name <{}>".format(addr), b64encode(b'123')
    h = mime.make_ac_header_value(addr=addr, keydata=keydata)
    assert "x@xy.z" in h
    r = mime.parse_ac_headervalue(h)
    assert not r.error
    assert r.keydata == keydata
    assert r.addr == "x@xy.z"
    assert not r.extra_attr


def test_parse_autocrypt_addr_case_insensitive(datadir):
    msg = mime.parse_message_from_string(datadir.read("rsa2048-simple-casing.eml"))
    r = mime.parse_one_ac_header_from_msg(msg)
    assert r.addr == "alice@testsuite.autocrypt.org"


def test_make_and_parse_header_prefer_encrypt():
    addr, keydata = "x@xy.z", b64encode(b'123')
    h = mime.make_ac_header_value(addr=addr, keydata=keydata, prefer_encrypt="notset")
    r = mime.parse_ac_headervalue(h)
    assert "notset" in r.error
    assert not r.keydata


def test_get_delivered_to():
    msg = mime.gen_mail_msg(From="a@a.org", To=["b@b.org"], _dto=True)
    assert mime.get_delivered_to(msg) == "b@b.org"

    msg = mime.gen_mail_msg(From="a@a.org", To=["b@b.org"], _dto=False)
    assert mime.get_delivered_to(msg, "z@b.org") == "z@b.org"

    with pytest.raises(ValueError):
        mime.get_delivered_to(msg)


@pytest.mark.parametrize("input,output", [
    ("Simple <x@x.org>", "x@x.org"),
    ("=?utf-8?Q?Bj=C3=B6rn?= <x@x.org>", "x@x.org"),
    ("x <x@k\366nig.net>", "x@könig.net"),
])
def test_parse_email_addr(input, output):
    addr = mime.parse_email_addr(input)
    assert isinstance(addr, six.text_type)
    assert addr == output


@pytest.mark.parametrize("input", ["", "lkqwje", ";;"])
def test_parse_ac_headervalue_bad_input(input):
    r = mime.parse_ac_headervalue(input)
    assert r.error


class TestEmailCorpus:
    def test_rsa2048_simple(self, datadir, bingpg):
        r = datadir.parse_ac_header_from_email("rsa2048-simple.eml")
        assert r.addr == "alice@testsuite.autocrypt.org", r
        assert r.prefer_encrypt == "nopreference"
        bingpg.import_keydata(r.keydata)

    def test_rsa2048_explicit_type(self, datadir, bingpg):
        r = datadir.parse_ac_header_from_email("rsa2048-explicit-type.eml")
        assert r.error
        assert not r.keydata

    def test_rsa2048_unknown_non_critical(self, datadir, bingpg):
        r = datadir.parse_ac_header_from_email("rsa2048-unknown-non-critical.eml")
        assert r.addr == "alice@testsuite.autocrypt.org"
        assert r.extra_attr["_monkey"] == "ignore"
        bingpg.import_keydata(r.keydata)

    def test_rsa2048_unknown_critical(self, datadir):
        r = datadir.parse_ac_header_from_email("rsa2048-unknown-critical.eml")
        assert "unknown critical attr 'danger'" in r.error

    def test_rsa2048_from_not_match(self, datadir):
        r = datadir.parse_ac_header_from_email("rsa2048-from-not-match.eml")
        assert "does not match" in r.error

    def test_unknown_type(self, datadir):
        r = datadir.parse_ac_header_from_email("unknown-type.eml")
        assert "unknown critical attr 'type'" in r.error
