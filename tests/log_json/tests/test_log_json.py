# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2026 OpenAI
#
# SPDX-License-Identifier: GPL-2.0-or-later

import importlib.util
import pathlib
import sys
import types


ROOT = pathlib.Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "modules/python/dionaea/log_json.py"


class DummyIHandlerLoader(object):
    pass


class DummyIHandler(object):
    def __init__(self, path):
        self.path = path


class DummyLoaderError(Exception):
    def __init__(self, msg, *args):
        self.msg = msg
        self.args = args


class CollectingHandler(object):
    def __init__(self):
        self.records = []

    def submit(self, data):
        self.records.append(data)


class Endpoint(object):
    def __init__(self, host, port, hostname=None):
        self.host = host
        self.port = port
        self.hostname = hostname


class Connection(object):
    def __init__(self):
        self.protocol = "http"
        self.transport = "tcp"
        self.local = Endpoint("192.0.2.10", 80)
        self.remote = Endpoint("198.51.100.25", 4444, "attacker.example")


def load_log_json_module():
    module_name = "test_log_json_module"

    fake_dionaea = types.ModuleType("dionaea")
    fake_dionaea.IHandlerLoader = DummyIHandlerLoader

    fake_core = types.ModuleType("dionaea.core")
    fake_core.ihandler = DummyIHandler

    fake_exception = types.ModuleType("dionaea.exception")
    fake_exception.LoaderError = DummyLoaderError

    saved_modules = {}
    for name, module in (
        ("dionaea", fake_dionaea),
        ("dionaea.core", fake_core),
        ("dionaea.exception", fake_exception),
    ):
        saved_modules[name] = sys.modules.get(name)
        sys.modules[name] = module

    try:
        spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, module in saved_modules.items():
            if module is None:
                del sys.modules[name]
            else:
                sys.modules[name] = module


def create_handler(log_json_module):
    handler = log_json_module.LogJsonHandler("*", config={
        "handlers": [],
    })
    handler.handlers = [CollectingHandler()]
    return handler


def test_download_complete_hash_emits_standalone_record():
    log_json_module = load_log_json_module()
    handler = create_handler(log_json_module)

    incident = types.SimpleNamespace(
        con=Connection(),
        file="/var/dionaea/binaries/44d88612fea8a8f36de82e1278abb02f",
        md5hash="44d88612fea8a8f36de82e1278abb02f",
        url="http://example.invalid/malware.exe",
    )

    handler.handle_incident_dionaea_download_complete_hash(incident)

    assert len(handler.handlers[0].records) == 1
    record = handler.handlers[0].records[0]
    assert "timestamp" in record
    assert record["connection"] == {
        "protocol": "http",
        "transport": "tcp",
    }
    assert record["dst_ip"] == "192.0.2.10"
    assert record["dst_port"] == 80
    assert record["src_hostname"] == "attacker.example"
    assert record["src_ip"] == "198.51.100.25"
    assert record["src_port"] == 4444
    assert record["download"] == {
        "file": "/var/dionaea/binaries/44d88612fea8a8f36de82e1278abb02f",
        "filename": "44d88612fea8a8f36de82e1278abb02f",
        "md5": "44d88612fea8a8f36de82e1278abb02f",
        "url": "http://example.invalid/malware.exe",
    }


def test_download_complete_hash_emits_for_repeated_files():
    log_json_module = load_log_json_module()
    handler = create_handler(log_json_module)

    incident = types.SimpleNamespace(
        con=Connection(),
        file="/var/dionaea/binaries/44d88612fea8a8f36de82e1278abb02f",
        md5hash="44d88612fea8a8f36de82e1278abb02f",
        url="http://example.invalid/malware.exe",
    )

    handler.handle_incident_dionaea_download_complete_hash(incident)
    handler.handle_incident_dionaea_download_complete_hash(incident)

    assert len(handler.handlers[0].records) == 2
    assert handler.handlers[0].records[0]["download"]["md5"] == incident.md5hash
    assert handler.handlers[0].records[1]["download"]["md5"] == incident.md5hash
