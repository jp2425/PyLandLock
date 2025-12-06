from src.pylandlock.landlock_struct import RulesetAttr


class CreateStructureService:

    def create_ruleset_struct(self, filesystem_values: list, networking_values: list, extra_flags: list) -> RulesetAttr:
        """
        Creates a structure with the pemrmissions for the ruleset
        It can receive a list of rules to apply
        :return: structure that represents the ruleset attributes / access
        """
        if len(filesystem_values) == 0 and len(networking_values) == 0:
            raise SystemExit("You cannot create a ruleset with no rules...")

        # filesystem
        ACCESS_FS = 0
        ACCESS_NET = 0
        EXTRA_FLAGS = 0
        for value in filesystem_values:
            ACCESS_FS = ACCESS_FS | value.value
        for value2 in networking_values:
            ACCESS_NET = ACCESS_NET | value2.value
        for value3 in extra_flags:
            EXTRA_FLAGS = EXTRA_FLAGS | value3.value

        return RulesetAttr(handled_access_fs=ACCESS_FS, handled_access_net=ACCESS_NET, scoped=EXTRA_FLAGS)
