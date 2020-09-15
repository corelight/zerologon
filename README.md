# Zerologon

## Summary

A Zeek detection package for
[CVE-2020-1472](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1472),
also known as Zerologon, which is a CVSS 10.0 privilege escalation
vulnerability against the Netlogon protocol for Windows Server domain
controllers.

## Notices

By default, both notices are raised:
* `Zerologon_Attempt` indicates the requisite number of login attempts
  were made within a short period of time.
* `Zerologon_Password_Change` indicates the above, and a successful
  password change occurred.
  
By `redef`ing `notice_on_exploit_only` to `T` in `cluster.zeek`, only
the `Zerologon_Password_Change` notice will be generated.

## Usage and Notes

* Tested on Zeek versions `3.3.0-dev.53-debug` and `3.2.0`, and
  Corelight Sensor v19. It should work with Zeek 3.0 and higher.
* This package will run in both clustered and non-clustered
  environments.
* Developed against the included attack PCAPs.

## References
* https://www.secura.com/blog/zero-logon
* https://www.secura.com/pathtoimg.php?id=2055
* https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc
