import os
import requests
from pylandlock import PyLandLock
from pylandlock.constants import LandLockAccessRights

# =============================
# Initialize LandLock
# =============================
lock = PyLandLock()
print("ABI version:", lock.detect_abi_version())

# =======================================================
# Sandbox flags - what you want to monitor / block
# ========================================================
fs_flags = [
    LandLockAccessRights.LANDLOCK_ACCESS_FS_EXECUTE,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_WRITE_FILE,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_FILE,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_DIR,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_REMOVE_DIR,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_REMOVE_FILE,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_CHAR,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_DIR,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_REG,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_SOCK,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_FIFO,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_BLOCK,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_SYM,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_REFER,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_TRUNCATE,
    LandLockAccessRights.LANDLOCK_ACCESS_FS_IOCTL_DEV,
]

net_flags = [
    LandLockAccessRights.LANDLOCK_ACCESS_NET_BIND_TCP,
    LandLockAccessRights.LANDLOCK_ACCESS_NET_CONNECT_TCP
]

scoped = []

memory_struct_fd = lock.create_ruleset(fs_flags, net_flags, scoped)

# =============================
# File and directory permissions
# =============================
ACCESS = LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_DIR.value | LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_FILE.value
lock.add_rule_fs_by_file(ACCESS, memory_struct_fd, ".")

# Essential system directories for Python, requests, and DNS
READ_ONLY = LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_FILE.value
lock.add_rule_fs_by_file(READ_ONLY, memory_struct_fd, "/etc/ssl/certs/")
lock.add_rule_fs_by_file(READ_ONLY, memory_struct_fd, "/etc/resolv.conf")
lock.add_rule_fs_by_file(READ_ONLY, memory_struct_fd, "/etc/hosts")
lock.add_rule_fs_by_file(READ_ONLY, memory_struct_fd, "/usr/lib/python3")
lock.add_rule_fs_by_file(READ_ONLY, memory_struct_fd, "/usr/lib/python3/dist-packages")
lock.add_rule_fs_by_file(READ_ONLY, memory_struct_fd, "/usr/lib/python3.12")
lock.add_rule_fs_by_file(READ_ONLY, memory_struct_fd, "/etc/apt/apt.conf.d/")

# /tmp with read and write permissions (cache, Python temporary files)
TMP_ACCESS = (
    LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_FILE.value |
    LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_DIR.value |
    LandLockAccessRights.LANDLOCK_ACCESS_FS_WRITE_FILE.value
)
lock.add_rule_fs_by_file(TMP_ACCESS, memory_struct_fd, "/tmp")

# =============================
# Network permissions
# =============================
ACCESS_NET = LandLockAccessRights.LANDLOCK_ACCESS_NET_CONNECT_TCP.value
lock.add_rule_net(ACCESS_NET, memory_struct_fd, 443)

# =============================
# Apply the sandbox
# =============================
lock.define_no_new_privileges()
lock.apply_landlock_sandbox(memory_struct_fd)

# =============================
# File read test
# =============================
with open("./README.md", "r") as test_file:
    print(test_file.read())

# /tmp directory listing test
print(os.listdir("/tmp"))

# ==========================================================================================
# HTTP request test - this should work, since we whitelisted connections to the 443 port
# ==========================================================================================
url = "https://google.com"
response = requests.get(url)
print("Status code:", response.status_code)
print("First 500 characters of the content:\n", response.text[:500])
