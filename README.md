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

## Usage

See [the example file](example.py) for an example.