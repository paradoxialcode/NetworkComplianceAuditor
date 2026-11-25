CISCO_GOOD = """version 17.9
hostname edge-r1
service timestamps log datetime msec
service password-encryption
!
enable secret 9 $9$SuperSecretHash
username admin secret 9 $9$AnotherHash
aaa new-model
login block-for 120 attempts 3 within 60
logging on
logging trap informational
logging host 10.0.1.9
ntp server 10.0.0.1
ntp server 10.0.0.2
no ip source-route
no ip http server
no ip http secure-server
ip ssh version 2
license udi pid C9300-24T sn FCW1234ABCD
radius server RAD1
 address ipv4 10.0.0.9 auth-port 1812
 key 7 RADIUSKEY123
banner login ^CAuthorized use only SECRETBANNER^C
snmp-server community Xk39sLong RO
snmp-server user mon grp v3 auth sha AUTHPASS999 priv aes 128 PRIVPASS999
ip access-list extended EDGE
 permit tcp any host 10.1.1.1 eq 443
 deny ip any any
interface GigabitEthernet0/0
 description uplink
 no ip redirects
 no ip directed-broadcast
 ip verify unicast source reachable-via rx
line vty 0 4
 exec-timeout 5 0
 access-class 10 in
 transport input ssh
"""

CISCO_BAD = """version 15.2
hostname lab-sw
enable password cisco123
username bob password 0 plaintext1
snmp-server community public RO
ip http server
ip source-route
access-list 101 permit ip any any
interface Vlan1
 ip redirects
 ip directed-broadcast
line vty 0 4
 password vtypass
 exec-timeout 0 0
 transport input telnet
"""

FORTI_GOOD = """#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin
config system global
    set hostname "fw1"
    set admintimeout 5
    set admin-lockout-threshold 3
    set pre-login-banner enable
end
config system admin
    edit "admin"
        set trusthost1 10.0.0.0 255.255.255.0
        set password ENC SH2abcdefSECRETENC
    next
end
config system interface
    edit "wan1"
        set allowaccess ping https ssh
        set icmp-redirect disable
    next
end
config system snmp community
    edit 1
        set name "Zq81LongCommunity"
        set status enable
    next
end
config system snmp user
    edit "mon"
        set auth-pwd ENC SNMPAUTHSECRET
    next
end
config system ntp
    config ntpserver
        edit 1
            set server "10.0.0.1"
        next
        edit 2
            set server "10.0.0.2"
        next
    end
end
config log syslogd setting
    set status enable
    set server "10.1.1.1"
    set severity information
end
config system replacemsg admin "pre_admin-disclaimer-text"
    set buffer "FORTIBANNERTEXT"
end
config user radius
    edit "r1"
        set server "10.0.0.5"
        set secret ENC RADIUSSECRETENC
    next
end
config firewall policy
    edit 2
        set srcintf "lan"
        set srcaddr "net1"
        set dstaddr "all"
        set service "HTTP"
        set action accept
    next
end
config system settings
    set strict-src-check enable
end
"""

FORTI_BAD = """#config-version=FGT60F-7.0.1-FW-build0157-210101:opmode=0:vdom=0:user=admin
config system global
    set hostname "fw2"
    set admintimeout 30
end
config system admin
    edit "admin"
        set password ENC SH2xyz
    next
end
config system interface
    edit "wan1"
        set allowaccess ping http telnet
        set icmp-redirect enable
    next
end
config system snmp community
    edit 1
        set name "public"
        set status enable
    next
end
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""
