# PyLandLock
A simple implementation of LandLock for python3.

Based on the [LandLock linux kernel documentation](https://docs.kernel.org/userspace-api/landlock.html) and on the [LandLock man page](https://man7.org/linux/man-pages/man7/landlock.7.html).

## How it works 

It is quite easy to use landlock on linux. Only 3 systemcalls are needed. The flow is something like this:

1. We create a `landlock_ruleset_attr` struct with everything LandLock will be monitoring;  
2. We create in memory a structure that will contain our rules. This is the struct that will have the allowlist for our program;  
3. Create a `landlock_path_beneath_attr` struct with everything we want to allow (aka, permissions, like read file, write file, read dir, ...)  
4. Get a fd for the target file/directory
5. Associate the permissions to the path, and add that rule to the in-memory struct
6. Say to the kernel that our process will not be able to get new privileges (required, otherwise we need more capabilities to use LandLock)  
7. Apply landlock rules!


## Limitations

Right now, it only limits filesystem operations. IN the future it would be interesting to limit also networking.

## Usage

```python
import os

from LandLock import LandLock
from LandLockAccessRights import LandLockAccessRights

# 1: detetar versão do ABI

lock = LandLock()
print(lock.detect_abi_version())

# cria um ruleset com tudo o qyue vai ser gerido / monitorizado pelo landlock
ruleset_struct, access = lock.create_ruleset_struct(
            LandLockAccessRights.LANDLOCK_ACCESS_FS_EXECUTE ,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_WRITE_FILE ,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_FILE ,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_DIR ,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_REMOVE_DIR,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_REMOVE_FILE,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_CHAR,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_DIR,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_REG,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_SOCK,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_FIFO,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_BLOCK,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_MAKE_SYM,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_REFER ,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_TRUNCATE ,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_IOCTL_DEV ,
                LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_DIR
                                                 )

# cria um ruleset em memória onde vamos dizer o que ele pode fazer
memory_struct_fd = lock.create_ruleset(ruleset_struct)

# what we allow. 1. acessps. 2- path
ACCESS = LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_DIR.value | LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_FILE.value
lock.add_rule(ACCESS, memory_struct_fd, lock.get_directory_file_descriptor("/home/dystic/Documents/LandLockTest"))

# what we allow. 1. acessps. 2- path
ACCESS = LandLockAccessRights.LANDLOCK_ACCESS_FS_READ_DIR.value
lock.add_rule(ACCESS, memory_struct_fd, lock.get_directory_file_descriptor("/tmp"))

#obrigatorio, senão precisamos de capabilities adicionais para aplicar
lock.define_no_new_privileges()
lock.apply_landlock_sandbox(memory_struct_fd)
#print(os.listdir("/home/dystic/Documents/LandLockTest"))

with open("/home/dystic/Documents/LandLockTest/teste","r") as test:
    #print(test.write("ola mundo"))
    print(test.read())

print(os.listdir("/tmp"))

```
