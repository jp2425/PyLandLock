from enum import Enum

class LandLockAccessRights(Enum):
    LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0  # 0x0001 (1)       - Executar ficheiros
    LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1  # 0x0002 (2)       - Escrever em ficheiros
    LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2  # 0x0004 (4)       - Ler ficheiros
    LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3  # 0x0008 (8)       - Ler/listar diretórios
    LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4  # 0x0010 (16)      - Remover diretórios
    LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5  # 0x0020 (32)      - Remover ficheiros
    LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6  # 0x0040 (64)      - Criar char devices
    LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7  # 0x0080 (128)     - Criar diretórios
    LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8  # 0x0100 (256)     - Criar ficheiros regulares
    LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9  # 0x0200 (512)     - Criar sockets Unix
    LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10  # 0x0400 (1024)    - Criar FIFOs/pipes nomeados
    LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11  # 0x0800 (2048)    - Criar block devices
    LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12  # 0x1000 (4096)    - Criar symlinks
    LANDLOCK_ACCESS_FS_REFER = 1 << 13  # 0x2000 (8192)    - Referenciar/linkar ficheiros
    LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14  # 0x4000 (16384)   - Truncar ficheiros
    LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15  # 0x8000 (32768)   - ioctl em dispositivos