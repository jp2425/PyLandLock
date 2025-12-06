import ctypes
import os
import ctypes.util
from src.pylandlock.constants.constants import Constants


class AuxService:

    def __init__(self):
        self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

    def syscall(self, num, *args):
        """Wrapper for syscall(), with error handling"""

        ret = self._libc.syscall(num, *args)
        if ret < 0:
            e = ctypes.get_errno()
            raise OSError(e, os.strerror(e))
        return ret

    def detect_abi_version(self):
        """
        Detects the ABI version by sending the syscall with no extra arguments.
        :return: ABI version (int)
        """
        abi = self.syscall(Constants.NR_CREATE, ctypes.c_void_p(0), ctypes.c_size_t(0), ctypes.c_uint32(1))
        if abi < 1:
            raise SystemExit("The kernel supports landlock, but not filesystem sandbox (ABI < 1)")
        return abi

    def get_directory_file_descriptor(self, path: str):
        """
        Gets the file descritptor for a directory
        :param path: path
        :return: fd
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f"Path {path} does not exist")

        pfd = os.open(path, os.O_PATH | os.O_CLOEXEC) # gets fd
        return pfd

    def define_no_new_privileges(self):
        """
        Prevents the process from gaining new privileges. Like in docker.
        SOurce: https://docs.kernel.org/userspace-api/landlock.html
        :return:
        """
        if self._libc.prctl(Constants.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError("Failed to define: PR_SET_NO_NEW_PRIVS")