#!/usr/bin/env python3
"""Unit tests for Xray config builder and key probe integration points."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import vless_utils

SAMPLE_KEYS = {
    "reality_tcp": "vless://4bdeee92-97e8-414d-bef6-ec1d5e2ab73b@5.181.201.36:443?flow=xtls-rprx-vision&pbk=r1MW0o1DsC6EEWN-KPKnoXszb1trxlKShRIgOpxqHBk&security=reality&sid=d98e7afec9c0c359&sni=estomin1.vodniki.monster&type=tcp&fp=android#🇪🇪 BALTICS",
    "reality_tcp_spx": "vless://4bdeee92-97e8-414d-bef6-ec1d5e2ab73b@latisha.loozerp.wiki:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=latisha.loozerp.wiki&pbk=bZpzmeWiEJyJQy0W2hHc34Nr6BuFXj1UDd80Cbwh1Fk&sid=ff776ff77be48b88&spx=%2F&type=tcp&fp=chrome#🇱🇻 BALTICS",
    "reality_tcp_allow_insecure": "vless://0de1047d-fadd-4075-a08e-2223c5dadd0a@dgh.clofidexa.ir:4660?encryption=none&type=tcp&flow=xtls-rprx-vision&security=reality&sni=primevideo.com&pbk=MvFnGYaVxMUdE4suSDZwkaI4FGHFAgfLLH_zUdIhZWI&sid=9701739aa23499cb&allowInsecure=1&fp=chrome#🇳🇱 NETHERLANDS",
    "reality_grpc": "vless://ddf09ad0-02dc-485b-9048-1038de5bebf0@es.cache-4d8a.com:443?encryption=none&type=grpc&security=reality&sni=es.cache-4d8a.com&serviceName=grpc&pbk=S6t9-gOX2mxWKNGvGSJ8NxDdlJy78d4gN2-wv2d0hFw&sid=8319913f2e5f5711&spx=%2F&allowInsecure=1&fp=android#🇳🇱 NETHERLANDS",
    "reality_xhttp": "vless://56eb043d-5683-4d48-94b2-688097c87854@146.75.59.20:443?encryption=none&extra=%7B%22scMaxEachPostBytes%22%3A1000000%2C%22scMaxConcurrentPosts%22%3A100%2C%22scMinPostsIntervalMs%22%3A30%2C%22xPaddingBytes%22%3A%22100-1000%22%2C%22noGRPCHeader%22%3Afalse%7D&host=lunex.store&path=%2FLunex&security=tls&sni=accounts.fastly.com&type=xhttp&fp=firefox#🇩🇪 GERMANY",
    "tls_ws": "vless://uuid@server.net:443?security=tls&sni=example.com&type=ws&path=/vless&host=proxy.net&fp=chrome#🇺🇸 WS",
    "tcp_plain": "vless://uuid@1.2.3.4:8080#Test",
}


def assert_true(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print("ok:", msg)


def test_build_configs():
    for name, key in SAMPLE_KEYS.items():
        parsed = vless_utils.parse_vless_key(key)
        assert_true(parsed is not None, f"{name}: parsed")
        config = vless_utils.build_xray_config(parsed, local_port=20000 + hash(name) % 10000)
        assert_true(isinstance(config, dict), f"{name}: config is dict")
        assert_true("outbounds" in config, f"{name}: outbounds")
        assert_true("inbounds" in config, f"{name}: inbounds")
        outbound = config["outbounds"][0]
        assert_true(outbound["protocol"] == "vless", f"{name}: protocol")
        stream = outbound["streamSettings"]
        assert_true(stream["security"] in ("none", "tls", "reality"), f"{name}: security={stream['security']}")
        assert_true(stream["network"] in ("tcp", "grpc", "xhttp", "ws", "http"), f"{name}: network={stream['network']}")
        print(f"{name}: {stream['network']}/{stream['security']}")


def test_reality_fields():
    key = SAMPLE_KEYS["reality_tcp"]
    parsed = vless_utils.parse_vless_key(key)
    config = vless_utils.build_xray_config(parsed, 20001)
    rs = config["outbounds"][0]["streamSettings"]["realitySettings"]
    assert_true(rs["publicKey"] == "r1MW0o1DsC6EEWN-KPKnoXszb1trxlKShRIgOpxqHBk", "reality publicKey")
    assert_true(rs["shortId"] == "d98e7afec9c0c359", "reality shortId")
    assert_true(rs["serverName"] == "estomin1.vodniki.monster", "reality serverName")
    assert_true(rs["fingerprint"] == "android", "reality fingerprint")
    assert_true(rs["spiderX"] == "/", "reality spiderX default")


def test_grpc_fields():
    key = SAMPLE_KEYS["reality_grpc"]
    parsed = vless_utils.parse_vless_key(key)
    config = vless_utils.build_xray_config(parsed, 20002)
    gs = config["outbounds"][0]["streamSettings"]["grpcSettings"]
    assert_true(gs["serviceName"] == "grpc", "grpc serviceName")


def test_xhttp_extra_json():
    key = SAMPLE_KEYS["reality_xhttp"]
    parsed = vless_utils.parse_vless_key(key)
    config = vless_utils.build_xray_config(parsed, 20003)
    xs = config["outbounds"][0]["streamSettings"]["xhttpSettings"]
    assert_true(xs["host"] == "lunex.store", "xhttp host")
    assert_true(xs["path"] == "/Lunex", "xhttp path")
    extra = xs.get("extra")
    assert_true(isinstance(extra, dict), "xhttp extra is dict")
    assert_true(extra.get("scMaxEachPostBytes") == 1000000, "xhttp scMaxEachPostBytes")
    assert_true(extra.get("noGRPCHeader") is False, "xhttp noGRPCHeader")


def test_flow_only_on_tcp():
    # flow must be on TCP user for TLS/Reality, absent elsewhere
    key = SAMPLE_KEYS["reality_tcp"]
    parsed = vless_utils.parse_vless_key(key)
    config = vless_utils.build_xray_config(parsed, 20004)
    user = config["outbounds"][0]["settings"]["vnext"][0]["users"][0]
    assert_true(user.get("flow") == "xtls-rprx-vision", "tcp flow")

    key2 = SAMPLE_KEYS["reality_grpc"]
    parsed2 = vless_utils.parse_vless_key(key2)
    config2 = vless_utils.build_xray_config(parsed2, 20005)
    user2 = config2["outbounds"][0]["settings"]["vnext"][0]["users"][0]
    assert_true("flow" not in user2, "grpc no flow")


def test_tcp_header_type_http():
    # TCP with headerType=http should use tcpSettings HTTP header
    key = "vless://abc@host:443?security=tls&sni=example.com&type=tcp&headerType=http&host=proxy.com&path=/&fp=chrome#T"
    parsed = vless_utils.parse_vless_key(key)
    config = vless_utils.build_xray_config(parsed, 20006)
    stream = config["outbounds"][0]["streamSettings"]
    assert_true("tcpSettings" in stream, "tcpSettings present")
    assert_true(stream["tcpSettings"]["header"]["type"] == "http", "tcpSettings header type")


def test_find_xray_local():
    found = vless_utils.find_xray_bin()
    if found:
        print("found xray:", found)
        assert_true(os.path.isfile(found), "xray binary exists")
    else:
        print("find_xray_bin: none locally (expected in CI/downloaded later)")


def test_port_allocation():
    p1 = vless_utils._allocate_local_port()
    p2 = vless_utils._allocate_local_port()
    assert_true(p1 != p2, "ports unique")
    assert_true(p2 == p1 + 1, "ports sequential")


if __name__ == "__main__":
    test_build_configs()
    test_reality_fields()
    test_grpc_fields()
    test_xhttp_extra_json()
    test_flow_only_on_tcp()
    test_tcp_header_type_http()
    test_find_xray_local()
    test_port_allocation()
    print("\nAll builder tests passed")
