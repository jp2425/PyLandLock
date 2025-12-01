import os
import sys
import ctypes
import ctypes.util

# C structures
class RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net",  ctypes.c_uint64), #não implementado para já
        ("scoped", ctypes.c_uint64)
    ]


class PathBeneath(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int),
    ]



# main class

class LandLock:

    # landlock's functions syscalls
    NR_CREATE = 444
    NR_ADD = 445
    NR_RESTRICT = 446

    # prctl constants
    PR_SET_NO_NEW_PRIVS = 38


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
        abi = self.syscall(self.NR_CREATE, ctypes.c_void_p(0), ctypes.c_size_t(0), ctypes.c_uint32(1))
        if abi < 1:
            raise SystemExit("The kernel supports landlock, but not filesystem sandbox (ABI < 1)")
        return abi

    def create_ruleset_struct(self, *args) -> (RulesetAttr, int):
        """
        Creates a structure with the pemrmissions for the ruleset
        It can receive a list of rules to apply
        :param args: Rules to apply (ex: create_ruleset(LANDLOCK_ACCESS_FS_READ_FILE, LANDLOCK_ACCESS_FS_READ_DIR)
        :return: structure that represents the ruleset attributes / access
        """
        if len(args) == 0:
            raise SystemExit("You cannot create a ruleset with no rules...")
        ACCESS = 0
        for value in args:
            ACCESS = ACCESS | value.value
        print("ACCESS: ",ACCESS)
        return RulesetAttr(handled_access_fs=ACCESS), ACCESS

    def create_ruleset(self, ruleset: RulesetAttr) -> ctypes.c_uint32:
        """
        Creates the ruleset using syscalls.
        This will be a ruleset that can be used to define what we allow the process to do.
        It returns a file descriptor that can be used to define on what the permissions defined earlier will be applied (like a directory / file)
        :param ruleset: ruleset structure
        :return: file descriptor of the created ruleset
        """
        ruleset_struct_size = ctypes.c_size_t(ctypes.sizeof(ruleset))
        ruleset_fd = self.syscall(
            self.NR_CREATE,
            ctypes.byref(ruleset), #pointer to the rulset struct
            ruleset_struct_size,
            ctypes.c_uint32(0)
        )
        return ruleset_fd

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

    def add_rule(self, access: ctypes.c_uint64, ruleset_fd: ctypes.c_uint32,file_descriptor: int):
        """
        Adds a rule to landlock. See: https://docs.kernel.org/userspace-api/landlock.html
        :param access: access structure
        :param file_descriptor: file descriptor of the target
        :return: None
        """
        rule = PathBeneath(allowed_access=access, parent_fd=file_descriptor) #struct

        # landlock_add_rule(ruleset_fd, rule_type, rule_attr, flags)
        LANDLOCK_RULE_PATH_BENEATH = 1

        value = self.syscall(
            self.NR_ADD,
            ruleset_fd, #what we monitor
            ctypes.c_int(LANDLOCK_RULE_PATH_BENEATH),
            ctypes.byref(rule), #pointer
            ctypes.c_uint32(0)
        )
        print("Add rule return value: ", value)
        print("Added the rule")
        os.close(file_descriptor) #close the file descriptor that points to the file on the filesystem.

    def define_no_new_privileges(self):
        """
        Prevents the process from gaining new privileges. Like in docker.
        SOurce: https://docs.kernel.org/userspace-api/landlock.html
        :return:
        """
        if self._libc.prctl(self.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError("Failed to define: PR_SET_NO_NEW_PRIVS")

    def apply_landlock_sandbox(self, ruleset_fd: ctypes.c_uint32 ):
        try:
            self.syscall(self.NR_RESTRICT, ruleset_fd, ctypes.c_uint32(0))
        except:
            print("Error applying the landlock sandbox")
        finally:
            os.close(int(ruleset_fd)) #closes the fd to the memory struct, we no longer need it