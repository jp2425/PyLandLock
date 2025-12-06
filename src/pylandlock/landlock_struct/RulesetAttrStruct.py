import ctypes


class RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net",  ctypes.c_uint64),
        ("scoped", ctypes.c_uint64)
    ]
