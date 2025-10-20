from binaryninja.log import Logger
from binaryninja import BinaryView, Settings
from binaryninja import user_plugin_path

import ctypes
from ctypes import c_char_p, c_void_p, c_size_t, c_uint8

from dataclasses import dataclass, field, asdict
from typing import Dict, List
import os
from os import path
import json

import yara_x as yr

logger = Logger(session_id=0, logger_name=__name__)

PLUGIN_RULES_SERIALIZED_FILE = "yarax.compiled.bin"
PLUGIN_SETTINGS_DIR = "BinYars Settings.Yara-X Directory.dir"
PLUGIN_SETTINGS_NAME = "BinYars Settings.BinYars Rust Lib.name"


@dataclass
class Pattern:
    identifier: str
    offset: int
    length: int
    data: str


@dataclass
class ConsoleLog:
    data: Dict[str, str] = field(default_factory=dict)


@dataclass
class MetaRule:
    rule: str
    desc: str
    identifiers: List[Pattern] = field(default_factory=list)
    console: List[ConsoleLog] = field(default_factory=list)


class Identifier:
    def __init__(self, name: str, offset: int, length: int, data: list[int]):
        self.name = name
        self.offset = offset
        self.length = length
        self.data = data

    def __repr__(self):
        return (
            f"Name: {self.name}\tOffset: {self.offset}\tLength: "
            f"{self.length}\tData: {self.data}"
        )


class ConsoleEntry:
    def __init__(self, key: str, value: str):
        self.key = key
        self.value = value

    @property
    def parent(self) -> str:
        """Everything before the last dot in the key, or the whole key if no dot."""
        if "." in self.key:
            return " ".join(self.key.rsplit(".", 1)[0])
        return self.key

    @property
    def child(self) -> str:
        """Everything after the last dot in the key, or the whole key if no dot."""
        if "." in self.key:
            return self.key.rsplit(".", 1)[1]
        return self.key


class ConsoleEntryGroup:
    def __init__(self, group: str, entries: List["ConsoleEntry"]):
        self.group = group  # The parent field name
        self.entries = entries  # List of ConsoleEntry objects

    def __repr__(self):
        return f"<ConsoleEntryGroup group={self.group} entries={len(self.entries)}>"

    def get_offset(self) -> int | None:
        """
        Returns the integer value of the child named 'offset' (case-insensitive), if it exists.
        Returns None if no such child is found or value cannot be converted to int.
        """
        for entry in self.entries:
            if entry.child.lower() == "offset":
                try:
                    return int(entry.value)
                except ValueError:
                    try:
                        return int(entry.value, 16)
                    except ValueError:
                        return None
        return None


class BinYarScanner:
    def __init__(
        self,
        yara_rule_dir=None,
        libbinyars=None,
    ):
        if yara_rule_dir is None:
            self.yar_dir = Settings().get_string(PLUGIN_SETTINGS_DIR)
        else:
            self.yar_dir = yara_rule_dir
        self.yar_compiled = path.join(self.yar_dir, PLUGIN_RULES_SERIALIZED_FILE)
        if libbinyars is None:
            rust_lib = Settings().get_string(PLUGIN_SETTINGS_NAME)
        else:
            rust_lib = libbinyars
        rust_lib = os.path.join(user_plugin_path(), rust_lib)
        self.lib = ctypes.CDLL(rust_lib)

        # Define scan_bytes signature
        self.lib.scan_bytes.argtypes = [
            ctypes.POINTER(c_uint8),  # *const u8
            c_size_t,  # len
            c_char_p,  # folder
            c_char_p,  # compiled_rules_file_name
        ]
        self.lib.scan_bytes.restype = c_void_p  # returns *const c_char

        # Define free_rust_string signature
        self.lib.free_rust_string.argtypes = [ctypes.c_void_p]
        self.lib.free_rust_string.restype = None

        # compile(rule: *const c_char) -> *const c_char
        self.lib.compile.argtypes = [c_char_p]
        self.lib.compile.restype = c_void_p

        # format(rule: *const c_char) -> *const c_char
        self.lib.format.argtypes = [c_char_p]
        self.lib.format.restype = c_void_p

        # module_info(bytes: *const u8, len: usize) -> *const c_char
        self.lib.module_info.argtypes = [ctypes.POINTER(c_uint8), c_size_t]
        self.lib.module_info.restype = c_void_p

        # Define argument and return types
        self.lib.scan_rule_against_bytes.argtypes = [
            ctypes.POINTER(c_uint8),  # pointer to bytes
            ctypes.c_size_t,  # length of bytes
            ctypes.c_char_p,  # rule string
        ]
        self.lib.scan_rule_against_bytes.restype = ctypes.c_void_p  # returns a C string

        self.lib.get_library_versions_json.restype = ctypes.c_void_p

    def get_yara_version(self):
        # Call the function
        result_ptr = self.lib.get_library_versions_json()

        # Free Rust string
        result = ctypes.string_at(result_ptr).decode("utf-8")

        # Free Rust string
        self.lib.free_rust_string(result_ptr)

        # Convert JSON back into Python dict
        versions = json.loads(result)
        return versions

    def precompile(self):
        if self.yar_dir is not None:
            compiler = yr.Compiler()
            for yar in self._file_yara_files(self.yar_dir):
                with open(yar, "r") as f:
                    compiler.add_source(f.read(), yar)
            rules = compiler.build()
            with open(self.yar_compiled, "wb") as f:
                rules.serialize_into(f)

    def _file_yara_files(self, dir):
        yar_files = []
        for root, dirs, files in os.walk(dir):
            for file in files:
                if file.lower().endswith(".yar"):
                    yar_files.append(os.path.join(root, file))
        return yar_files

    def get_metadata_string_field(self, meta: dict, field_name: str) -> str | None:
        """
        Look up a metadata field by name (case-insensitive) and return its string value if it exists.
        """
        if meta:
            for key, value in meta:
                if key.lower() == field_name.lower():
                    if isinstance(value, str):  # equivalent to MetaValue::String
                        return value
        return None

    def get_patterns(self, patterns, raw_bytes) -> list[Pattern]:
        """
        Convert yara_x::Patterns into a list of Pattern objects.
        """
        hit_patterns: list[Pattern] = []

        m: yr.Pattern
        for m in patterns:  # iterate over patterns
            n: yr.Match
            for n in m.matches:  # iterate over matches
                hit_patterns.append(
                    Pattern(
                        identifier=m.identifier,
                        offset=n.offset,
                        length=n.length,
                        data=[d for d in raw_bytes[n.offset : n.offset + n.length]],
                    )
                )
        return hit_patterns

    def scan(self, raw_bytes):
        # Prepare inputs
        data_ptr = (c_uint8 * len(raw_bytes))(*raw_bytes)
        folder_c = self.yar_dir.encode("utf-8")
        rules_c = self.yar_compiled.encode("utf-8")

        # Call Rust function
        result_ptr = self.lib.scan_bytes(data_ptr, len(raw_bytes), folder_c, rules_c)

        # Convert result back to Python string
        # if not result_ptr:
        #    return ""

        result = ctypes.string_at(result_ptr).decode("utf-8")

        # Free Rust string
        self.lib.free_rust_string(result_ptr)

        # If empty string -> treat as error/no results
        if result.strip() == "":
            return None

        # Otherwise parse JSON
        try:
            raw_list = json.loads(result)
            return [
                MetaRule(
                    rule=mr["rule"],
                    desc=mr["desc"],
                    identifiers=[
                        Pattern(
                            identifier=p["identifier"],
                            offset=p["offset"],
                            length=p["length"],
                            data=p["data"],
                        )
                        for p in mr.get("identifiers", [])
                    ],
                    console=[ConsoleEntry(data=c) for c in mr.get("console", [])],
                )
                for mr in raw_list
            ]
        except json.JSONDecodeError:
            return None

    def scan_rule_against_bytes(self, raw_bytes: bytes, rule: str) -> str:
        """
        Python wrapper for the Rust scan_rule_against_bytes function.
        """
        # Convert Python -> C types
        data_ptr = (c_uint8 * len(raw_bytes))(*raw_bytes)
        rule_bytes = rule.encode("utf-8")

        # Call Rust function
        result_ptr = self.lib.scan_rule_against_bytes(
            data_ptr, len(raw_bytes), rule_bytes
        )

        # Convert back to Python str
        result = ctypes.string_at(result_ptr).decode("utf-8")
        # Free Rust string
        self.lib.free_rust_string(result_ptr)

        # If empty string -> treat as error/no results
        if result.strip() == "":
            return None

        # Otherwise parse JSON
        try:
            raw_list = json.loads(result)
            return [
                MetaRule(
                    rule=mr["rule"],
                    desc=mr["desc"],
                    identifiers=[
                        Pattern(
                            identifier=p["identifier"],
                            offset=p["offset"],
                            length=p["length"],
                            data=p["data"],
                        )
                        for p in mr.get("identifiers", [])
                    ],
                    console=[ConsoleEntry(data=c) for c in mr.get("console", [])],
                )
                for mr in raw_list
            ]
        except json.JSONDecodeError:
            # Return raw string if JSON failed
            return None

    def save(self, bv: BinaryView, hits: list[MetaRule], key: str):
        bv.store_metadata(key, json.dumps([asdict(mr) for mr in hits]))

    def get_module_fields(self, raw_bytes):
        data_ptr = (c_uint8 * len(raw_bytes))(*raw_bytes)
        ptr = self.lib.module_info(data_ptr, len(raw_bytes))
        result = ctypes.cast(ptr, c_char_p).value.decode()
        self.lib.free_rust_string(ptr)  # Free memory allocated by Rust
        if result.strip() == "":
            return None
        return result

    def rule_compiles(self, rule_text: str) -> str | None:
        rule_bytes = rule_text.encode("utf-8")
        ptr = self.lib.compile(rule_bytes)
        result = ctypes.cast(ptr, c_char_p).value.decode()
        self.lib.free_rust_string(ptr)  # Free memory allocated by Rust
        if result.strip() == "":
            return None
        return result

    def rule_fmt(self, rule_text: str) -> str | None:
        rule_bytes = rule_text.encode("utf-8")
        ptr = self.lib.format(rule_bytes)
        result = ctypes.cast(ptr, c_char_p).value.decode()
        self.lib.free_rust_string(ptr)  # Free memory allocated by Rust
        if result.strip() == "":
            return None
        return result
