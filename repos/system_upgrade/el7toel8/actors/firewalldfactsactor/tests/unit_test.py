import xml.etree.ElementTree as ElementTree

from leapp.libraries.actor import private


def test_firewalldfactsactor_direct():
    root = ElementTree.fromstring(
        '''<?xml version="1.0" encoding="utf-8"?>
           <direct>
             <passthrough ipv="eb">-t broute -I BROUTING 1 -j ACCEPT</passthrough>
           </direct>
        ''')
    assert private.getEbtablesTablesInUse(root) == ['broute']

    root = ElementTree.fromstring(
        '''<?xml version="1.0" encoding="utf-8"?>
           <direct>
             <rule priority="1" table="broute" ipv="eb" chain="BROUTING">-j ACCEPT</rule>
           </direct>
        ''')
    assert private.getEbtablesTablesInUse(root) == ['broute']

    root = ElementTree.fromstring(
        '''<?xml version="1.0" encoding="utf-8"?>
           <direct>
             <rule priority="1" table="broute" ipv="eb" chain="BROUTING">-j ACCEPT</rule>
             <rule priority="1" table="filter" ipv="ipv4" chain="INPUT">-j ACCEPT</rule>
             <passthrough ipv="eb">-t nat -I PREROUTING 1 -j ACCEPT</passthrough>
           </direct>
        ''')
    assert set(private.getEbtablesTablesInUse(root)) == set(['broute', 'nat'])


def test_firewalldfactsactor_firewallConfigCommand():
    root = ElementTree.fromstring(
        '''<?xml version="1.0" encoding="utf-8"?>
           <whitelist>
             <command name="/usr/bin/python -Es /usr/bin/firewall-config"/>
             <command name="/usr/bin/foobar"/>
             <selinux context="system_u:system_r:NetworkManager_t:s0"/>
             <selinux context="system_u:system_r:virtd_t:s0-s0:c0.c1023"/>
             <user id="0"/>
           </whitelist>
        ''')
    assert private.getLockdownFirewallConfigCommand(root) == '/usr/bin/python -Es /usr/bin/firewall-config'

    root = ElementTree.fromstring(
        '''<?xml version="1.0" encoding="utf-8"?>
           <whitelist>
             <command name="/usr/bin/foobar"/>
           </whitelist>
        ''')
    assert private.getLockdownFirewallConfigCommand(root) == ''

    root = ElementTree.fromstring(
        '''<?xml version="1.0" encoding="utf-8"?>
           <whitelist>
             <command name="/usr/libexec/platform-python -s /usr/bin/firewall-config"/>
             <selinux context="system_u:system_r:NetworkManager_t:s0"/>
             <selinux context="system_u:system_r:virtd_t:s0-s0:c0.c1023"/>
             <user id="0"/>
           </whitelist>
        ''')
    assert private.getLockdownFirewallConfigCommand(root) == '/usr/libexec/platform-python -s /usr/bin/firewall-config'


def test_firewalldfactsactor_ipsetTypes():
    root = ElementTree.fromstring(
        '''<?xml version="1.0" encoding="utf-8"?>
           <ipset type="hash:ip">
             <short>My Ipset</short>
             <description>description</description>
             <entry>1.2.3.4</entry>
           </ipset>
        ''')
    assert private.getIpsetTypesInUse(root) == ['hash:ip']

    root = ElementTree.fromstring(
        '''<?xml version="1.0" encoding="utf-8"?>
           <ipset type="hash:net,port">
             <short>My Ipset</short>
             <description>description</description>
           </ipset>
        ''')
    assert private.getIpsetTypesInUse(root) == ['hash:net,port']
