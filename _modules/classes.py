# MARK: Target Class

class Target:
    def __init__(
        self, FQDN, IP, IPVersion, Port, SNMPVersion=None, CommunityString=None,
        Username=None, AuthPwd=None, AuthProto={'Name': None, 'Class': None},
        PrivPwd=None, PrivProto={'Name': None, 'Class': None}, Access=False
    ):
        self.FQDN = FQDN  # Some provided targets may not have a DNS FQDN. If they don't, this will be the IP address also.
        self.IP = IP
        self.IPVersion = IPVersion
        self.SNMPVersion = SNMPVersion
        self.CommunityString = CommunityString
        self.Username = Username
        self.AuthPwd = AuthPwd
        self.AuthProto = AuthProto  # ['Name': 'NicknameAlgo', 'Class': USMAlgoClass]
        self.PrivPwd = PrivPwd
        self.PrivProto = PrivProto  # ['Name': 'NicknameAlgo', 'Class': USMAlgoClass]
        self.Port = Port
        # We'll use this below attribute to keep track of if an entry needs more spraying
        # Like don't spray usernames on this instance if a community string was successfully found
        # And vice versa.
        self.Access = Access

    def __str__(self):
        if self.PrivProto:
            return f"[d]   {self.FQDN}:{self.Port}/{self.SNMPVersion} via {self.CommunityString}/{self.Username}/{self.AuthPwd}/{self.AuthProto['Name']}/{self.PrivPwd}/{self.PrivProto['Name']}, Access: {self.Access}"
        elif self.AuthProto:
            return f"[d]   {self.FQDN}:{self.Port}/{self.SNMPVersion} via {self.CommunityString}/{self.Username}/{self.AuthPwd}/{self.AuthProto['Name']}/None/None, Access: {self.Access}"
        else:
            return f"[d]   {self.FQDN}:{self.Port}/{self.SNMPVersion} via {self.CommunityString}/{self.Username}/None/None/None/None, Access: {self.Access}"

    @property
    def IPVersion(self):
        return self._IPVersion

    @IPVersion.setter
    def IPVersion(self, value):
        if value not in ["v4", "v6", 'both']:
            # If presented the option between v4 or v6, we mark it based upon the first resolved record's type
            raise ValueError("IPVersion must be 'v4' or 'v6'.")
        self._IPVersion = value

    @property
    def SNMPVersion(self):
        return self._SNMPVersion

    @SNMPVersion.setter
    def SNMPVersion(self, value):
        if value not in ["v1", "v2c", "v3"]:
            raise ValueError("SNMPVersion must be 'v1', 'v2c, or 'v3'.")
        self._SNMPVersion = value

    def __eq__(self, other):
        if not isinstance(other, Target):
            return False
        return (
            self.FQDN == other.FQDN and
            self.Port == other.Port and
            self.SNMPVersion == other.SNMPVersion and
            self.CommunityString == other.CommunityString and
            self.Username == other.Username and
            self.AuthPwd == other.AuthPwd and
            self.AuthProto == other.AuthProto and
            self.PrivPwd == other.PrivPwd and
            self.PrivProto == other.PrivProto
        )

    def __hash__(self):
        return hash((
            self.FQDN,
            self.Port,
            self.SNMPVersion,
            self.CommunityString,
            self.Username,
            self.AuthPwd,
            str(self.AuthProto),
            self.PrivPwd,
            str(self.PrivProto)
        ))
