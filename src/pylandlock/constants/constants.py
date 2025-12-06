class Constants:
    # landlock's functions syscalls
    NR_CREATE = 444
    NR_ADD = 445
    NR_RESTRICT = 446

    # prctl constants
    PR_SET_NO_NEW_PRIVS = 38

    # types of rules: network or filesystem
    LANDLOCK_RULE_PATH_BENEATH = 1  # filesystm rule
    LANDLOCK_RULE_NET_PORT = 2  # network rule