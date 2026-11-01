"""IOAccelerator properties straight from IOKit, without spawning ``ioreg``.

``sensors_svc._gpu()`` ran ``ioreg -a -r -d 1 -c IOAccelerator`` on every
light dashboard tick and every metrics sample: about 24 ms of child CPU, 9 ms
in the panel to spawn and parse it, and 100 KB of XML written through two temp
files, to read four properties of one registry entry.  This asks IOKit for
exactly those properties, in under a millisecond.

:func:`accelerator_entries` answers the same per-entry dicts ``ioreg -a``
yields for the keys ``_gpu()`` reads, or None whenever it cannot: not macOS, a
framework that does not load, a lookup that fails, or the switch below.  The
caller then falls back to ``ioreg``, so nothing is lost on an odd host.

``SERVERHUB_NO_NATIVE_GPU`` turns it off: the test suite sets it so the
stubbed-``ioreg`` tests keep exercising the parser.
"""
from __future__ import annotations

import ctypes
import os
import sys
import threading

_IOKIT = "/System/Library/Frameworks/IOKit.framework/IOKit"
_CORE_FOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
_UTF8 = 0x08000100  # kCFStringEncodingUTF8
_SINT64 = 4  # kCFNumberSInt64Type
_FLOAT64 = 6  # kCFNumberFloat64Type
_NAME_SIZE = 128  # io_name_t
#: The properties ``sensors_svc._gpu()`` reads.  ``IORegistryEntryName`` is not
#: a property; it comes from IORegistryEntryGetName, as ``ioreg`` does.
PROPERTIES = ("PerformanceStatistics", "model", "Model", "IONameMatched")

_CONTROL_FLOW = (KeyboardInterrupt, SystemExit)
_ON_MACOS = sys.platform == "darwin"
_lock = threading.Lock()
_reader: _Reader | None = None
_unavailable = False


class _Reader:
    """The IOKit / CoreFoundation calls the GPU sample needs, typed once.

    Every function that returns a pointer is declared ``c_void_p``: ctypes'
    default ``int`` result would truncate a 64-bit CF reference.
    """

    def __init__(self) -> None:
        iokit = ctypes.CDLL(_IOKIT)
        cf = ctypes.CDLL(_CORE_FOUNDATION)
        vp, u32 = ctypes.c_void_p, ctypes.c_uint32

        def fn(lib, name, restype, *argtypes):
            f = getattr(lib, name)
            f.restype = restype
            f.argtypes = list(argtypes)
            return f

        self.matching = fn(iokit, "IOServiceMatching", vp, ctypes.c_char_p)
        self.services = fn(
            iokit, "IOServiceGetMatchingServices", ctypes.c_int, u32, vp, ctypes.POINTER(u32),
        )
        self.next = fn(iokit, "IOIteratorNext", u32, u32)
        self.prop = fn(iokit, "IORegistryEntryCreateCFProperty", vp, u32, vp, vp, u32)
        self.name = fn(iokit, "IORegistryEntryGetName", ctypes.c_int, u32, ctypes.c_char_p)
        self.release_object = fn(iokit, "IOObjectRelease", ctypes.c_int, u32)
        cfstr = fn(cf, "CFStringCreateWithCString", vp, vp, ctypes.c_char_p, u32)
        self.release = fn(cf, "CFRelease", None, vp)
        self.type_of = fn(cf, "CFGetTypeID", ctypes.c_ulong, vp)
        self.dict_count = fn(cf, "CFDictionaryGetCount", ctypes.c_long, vp)
        self.dict_items = fn(
            cf, "CFDictionaryGetKeysAndValues", None, vp, ctypes.POINTER(vp), ctypes.POINTER(vp),
        )
        self.is_float = fn(cf, "CFNumberIsFloatType", ctypes.c_bool, vp)
        self.number = fn(cf, "CFNumberGetValue", ctypes.c_bool, vp, ctypes.c_long, vp)
        self.str_len = fn(cf, "CFStringGetLength", ctypes.c_long, vp)
        self.str_max = fn(cf, "CFStringGetMaximumSizeForEncoding", ctypes.c_long, ctypes.c_long, u32)
        self.str_get = fn(cf, "CFStringGetCString", ctypes.c_bool, vp, ctypes.c_char_p, ctypes.c_long, u32)
        self.boolean = fn(cf, "CFBooleanGetValue", ctypes.c_bool, vp)
        self.data_len = fn(cf, "CFDataGetLength", ctypes.c_long, vp)
        self.data_ptr = fn(cf, "CFDataGetBytePtr", vp, vp)
        self.t_dict = fn(cf, "CFDictionaryGetTypeID", ctypes.c_ulong)()
        self.t_number = fn(cf, "CFNumberGetTypeID", ctypes.c_ulong)()
        self.t_string = fn(cf, "CFStringGetTypeID", ctypes.c_ulong)()
        self.t_bool = fn(cf, "CFBooleanGetTypeID", ctypes.c_ulong)()
        self.t_data = fn(cf, "CFDataGetTypeID", ctypes.c_ulong)()
        # Property names as CFStrings, made once and kept for the process.
        self.keys = {key: cfstr(None, key.encode(), _UTF8) for key in PROPERTIES}
        if not all(self.keys.values()):
            raise OSError("CFStringCreateWithCString failed")

    def _text(self, ref) -> str | None:
        size = self.str_max(self.str_len(ref), _UTF8) + 1
        if size < 1 or size > 1 << 20:
            return None
        buf = ctypes.create_string_buffer(size)
        if not self.str_get(ref, buf, size, _UTF8):
            return None
        return buf.value.decode("utf-8", "replace")

    def _value(self, ref, depth: int = 0):
        """A CFString, CFNumber, CFBoolean, CFData or CFDictionary as Python.

        The same types ``plistlib`` gives for ``ioreg -a``: an Intel Mac's
        ``model`` is CFData there, and ``_gpu_model`` decodes the bytes.  Any
        other type answers None and its key is left out.
        """
        kind = self.type_of(ref)
        if kind == self.t_string:
            return self._text(ref)
        if kind == self.t_data:
            size = self.data_len(ref)
            ptr = self.data_ptr(ref)
            if size == 0:
                return b""
            if size < 0 or size > 1 << 20 or not ptr:
                return None
            return ctypes.string_at(ptr, size)
        if kind == self.t_number:
            if self.is_float(ref):
                real = ctypes.c_double()
                return real.value if self.number(ref, _FLOAT64, ctypes.byref(real)) else None
            whole = ctypes.c_int64()
            return whole.value if self.number(ref, _SINT64, ctypes.byref(whole)) else None
        if kind == self.t_bool:
            return bool(self.boolean(ref))
        if kind == self.t_dict and depth < 2:
            count = self.dict_count(ref)
            if count <= 0 or count > 4096:
                return {}
            keys = (ctypes.c_void_p * count)()
            values = (ctypes.c_void_p * count)()
            self.dict_items(ref, keys, values)
            out = {}
            for key, value in zip(keys, values):
                if not key or not value or self.type_of(key) != self.t_string:
                    continue
                name = self._text(key)
                if name is not None:
                    out[name] = self._value(value, depth + 1)
            return out
        return None

    def entries(self) -> list[dict] | None:
        """One dict per IOAccelerator service, holding the keys ``_gpu()`` reads."""
        matching = self.matching(b"IOAccelerator")
        if not matching:
            return None
        iterator = ctypes.c_uint32(0)
        # Consumes the matching dictionary whether it succeeds or not.
        if self.services(0, matching, ctypes.byref(iterator)) != 0:
            return None
        out = []
        try:
            while True:
                entry = self.next(iterator)
                if not entry:
                    break
                try:
                    row = {}
                    for key, cf_key in self.keys.items():
                        ref = self.prop(entry, cf_key, None, 0)
                        if not ref:
                            continue
                        try:
                            value = self._value(ref)
                        finally:
                            self.release(ref)
                        if value is not None:
                            row[key] = value
                    buf = ctypes.create_string_buffer(_NAME_SIZE)
                    if self.name(entry, buf) == 0 and buf.value:
                        row["IORegistryEntryName"] = buf.value.decode("utf-8", "replace")
                    out.append(row)
                finally:
                    self.release_object(entry)
        finally:
            self.release_object(iterator.value)
        return out


def _get_reader() -> _Reader | None:
    global _reader, _unavailable
    if _reader is not None or _unavailable:
        return _reader
    with _lock:
        if _reader is None and not _unavailable:
            try:
                _reader = _Reader()
            except _CONTROL_FLOW:
                raise
            except BaseException:
                # A framework that does not load will not load later either.
                _unavailable = True
    return _reader


def accelerator_entries() -> list[dict] | None:
    """IOAccelerator entries as ``ioreg -a`` shows them, or None to use ioreg."""
    if os.environ.get("SERVERHUB_NO_NATIVE_GPU") or not _ON_MACOS:
        return None
    reader = _get_reader()
    if reader is None:
        return None
    try:
        return reader.entries()
    except _CONTROL_FLOW:
        raise
    except BaseException:
        return None
