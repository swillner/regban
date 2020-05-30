# regban

* work in progress: currently works as a proof-of-concept *

RegBan (*Reg*ular expression IP *Ban*ning) parses command output (e.g. `tail` of log files, `docker log` output, ...) for specified regular expressions representing failed login attempts by bots. Following a scoring system the parsed source IPs (v4 and v6) are banned for a customized amount of time using nftables sets (next-gen iptables).

Inspiration for this project is [fail2ban](http://fail2ban.org/wiki/index.php/Main_Page), for which it is meant to be a high-performance, light-weight alternative.

* Documentation coming soon *
