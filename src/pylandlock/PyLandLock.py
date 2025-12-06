import os
import ctypes
from src.pylandlock.service.AuxService import AuxService
from src.pylandlock.service.CreateStructureService import CreateStructureService
from src.pylandlock.landlock_struct import *
from src.pylandlock.constants import Constants
# main class

class PyLandLock:


    def __init__(self):
        self._aux = AuxService()
        self._struct = CreateStructureService()

    def detect_abi_version(self):
        return self._aux.detect_abi_version()

    def create_ruleset(self, filesystem_values: list, networking_values: list, extra_flags: list) -> ctypes.c_uint32:
        """
        Creates the ruleset using syscalls.
        This will be a ruleset that can be used to define what we allow the process to do.
        It returns a file descriptor that can be used to define on what the permissions defined earlier will be applied (like a directory / file)
        :return: file descriptor of the created ruleset
        """
        ruleset = self._struct.create_ruleset_struct(filesystem_values, networking_values, extra_flags)
        ruleset_struct_size = ctypes.c_size_t(ctypes.sizeof(ruleset))
        ruleset_fd = self._aux.syscall(
            Constants.NR_CREATE,
            ctypes.byref(ruleset), #pointer to the rulset struct
            ruleset_struct_size,
            ctypes.c_uint32(0)
        )
        return ruleset_fd

    def add_rule_fs_by_file(self, access: ctypes.c_uint64, ruleset_fd: ctypes.c_uint32, file_path: str):

        fd = self._aux.get_directory_file_descriptor(file_path)
        return self.add_rule_fs(access, ruleset_fd, fd)


    def add_rule_fs(self, access: ctypes.c_uint64, ruleset_fd: ctypes.c_uint32, file_descriptor: int) -> int:
        """
        Adds a rule to landlock related to filesystem access. See: https://docs.kernel.org/userspace-api/landlock.html
        :param access: access structure
        :param file_descriptor: file descriptor of the target
        :return: None
        """

        rule = FilesystemRule(allowed_access=access, parent_fd=file_descriptor) #struct
        value = self._aux.syscall(
            Constants.NR_ADD,
            ruleset_fd, #what we monitor
            ctypes.c_int(Constants.LANDLOCK_RULE_PATH_BENEATH),
            ctypes.byref(rule), #pointer
            ctypes.c_uint32(0)
        )
        os.close(file_descriptor) #close the file descriptor that points to the file on the filesystem.
        return value

    def add_rule_net(self, access: ctypes.c_uint64, ruleset_fd: ctypes.c_uint32, port: int):
        """
        Adds a rule to landlock related to network access. See: https://docs.kernel.org/userspace-api/landlock.html
        You can add two types of rules: LANDLOCK_ACCESS_NET_CONNECT_TCP, that allows to connect to certain port, or LANDLOCK_ACCESS_NET_BIND_TCP, that allows to bind to a certain port.
        :param access: access structure
        :param port: port number
        :return: None
        """
        rule = NetworkRule(allowed_access=access, port=port) #struct

        value = self._aux.syscall(
            Constants.NR_ADD,
            ruleset_fd, #what we monitor
            ctypes.c_int(Constants.LANDLOCK_RULE_NET_PORT),
            ctypes.byref(rule), #pointer
            ctypes.c_uint32(0)
        )
        print("Add rule return value: ", value)
        print("Added the rule")

    def define_no_new_privileges(self):
        """
        Prevents the process from gaining new privileges. Like in docker.
        SOurce: https://docs.kernel.org/userspace-api/landlock.html
        :return:
        """
        self._aux.define_no_new_privileges()

    def apply_landlock_sandbox(self, ruleset_fd: ctypes.c_uint32):
        try:
            self._aux.syscall(Constants.NR_RESTRICT, ruleset_fd, ctypes.c_uint32(0))
        except:
            print("Error applying the landlock sandbox")
        finally:
            os.close(int(ruleset_fd)) #closes the fd to the memory struct, we no longer need it