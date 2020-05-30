# RegBan

**work in progress: currently runs as a proof-of-concept**

RegBan (*Reg*ular expression IP *Ban*ning) parses command output (e.g. `tail` of log files, `docker log` output, ...) for specified regular expressions representing failed login attempts by bots. Following a scoring system the parsed source IPs (v4 and v6) are banned for a customized amount of time using `nftables` (next-gen `iptables`) sets.

Inspiration for this project is [fail2ban](http://fail2ban.org), for which it is meant to be a high-performance, light-weight alternative. Though not as flexible as fail2ban, its low-level C/C++ implementation directly uses the libnftnl system library and follows the Unix philosophy of "doing one thing and doing it well": it does not directly watch log files (`tail` is much better at that) and it does not deal with unbanning after a timeout by itself (that is much more efficient by directly using the `nftables` timeout feature).

**Documentation coming soon**
