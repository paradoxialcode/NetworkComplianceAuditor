# Check schema + baseline field contract (Part C)

## One check = one YAML entry
| key | meaning |
|---|---|
| id | unique, e.g. MGT-001 |
| title / description | shown in findings and reports |
| category | must match the file name (management, authentication, logging, network_filtering) |
| severity | critical / high / medium / low |
| applies_to | vendors: cisco, fortinet, junos |
| field | dotted path into the SecurityBaseline (`group.name`) |
| operator | equals, not_equals, gte, lte, gt, lt, in, not_in, contains, not_contains, matches |
| expected | value to compare with |
| on_missing | pass / fail / skip when the field is absent from the baseline |
| nist | NIST SP 800-53 control IDs |
| remediation_key | must exist in data/remediation/remediation_keys.yaml |

## Fields the checks read (needed from Part A's SecurityBaseline)
| field | type | note |
|---|---|---|
| management.telnet_enabled | bool | |
| management.ssh_enabled | bool | |
| management.ssh_version | int | 2 if v2 only |
| management.http_server_enabled | bool | |
| management.exec_timeout_minutes | int | "no timeout" (Cisco 0) -> store as a huge number or leave missing |
| management.snmp_default_community | bool | true if public/private used |
| management.login_banner_present | bool | |
| auth.aaa_enabled | bool | |
| auth.remote_auth_server_count | int | TACACS+/RADIUS |
| auth.password_encryption_enabled | bool | |
| auth.plaintext_password_count | int | |
| auth.max_login_attempts | int | |
| auth.privileged_secret_set | bool | |
| logging.enabled | bool | |
| logging.remote_server_count | int | |
| logging.timestamps_enabled | bool | |
| logging.ntp_server_count | int | |
| logging.trap_level_numeric | int | syslog severity 0-7 |
| filtering.ip_source_route_enabled | bool | |
| filtering.directed_broadcast_enabled | bool | |
| filtering.icmp_redirects_enabled | bool | |
| filtering.mgmt_access_restricted | bool | |
| filtering.permit_any_any_count | int | |
| filtering.antispoofing_enabled | bool | |
