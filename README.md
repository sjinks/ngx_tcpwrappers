# ngx_tcpwrappers [![Build Status](https://travis-ci.org/sjinks/ngx_tcpwrappers.svg?branch=master)](https://travis-ci.org/sjinks/ngx_tcpwrappers)

TCP Wrapper is a host-based networking ACL system, used to filter network access to Internet Protocol servers on
Unix-like operating systems such as Linux or BSD. It allows host or subnetwork IP addresses, names and/or ident
query replies, to be used as tokens on which to filter for access control purposes. Details are [here](http://linux.die.net/man/5/hosts_access).

TCP Wrapper is very convenient to use for anti-worm protection (e.g., in combination with DenyHosts, BlackHosts, fail2ban),
in particular, to defend against HTTP-based scans.

One of the biggests TCP Wrappers advantages are ACL dynamic configuration (deny rules can be added by the
Web Application Firewall and there is no need to restart or reload nginx) and simple configuration files.

Unfortunately, nginx does not support TCP Wrappers out of the box. Fortunately, this module fixes this.

It should be noted that TCP Wrappers have several pecularities you should know about:
* the most disappointing thing is that libwrap (library implementing TCP Wrappers functionality) is not a thread safe library.
In other words, if two threads try to simultaneously use libwrap, the results could be weird.
This is because libwrap uses non-reentrant functions like `strtok()`, `gethostbyname()`, `gethostbyaddr()` etc.
If nginx is built with threading support (does it work yet?), use of libwrap can lead to performance penalties
(because access to libwrap functions will have to be serialized). If nginx is configured without threading support
(this is the default for Linux), everything is OK.
* dynamic ACL configuration comes at a price: libwrap will read and parse `/etc/hosts.allow` and `/etc/hosts.deny`
on every request; this may be an issue for high-loaded projects.

# Build

Because nginx does not support dynamic modules, it will have to be rebuilt from the source.
Assuming that nginx source code is located in `~/nginx` and the source code of ngx_tcpwrappers is in `~/nginx/ngx_tcpwrappers`,
the build process will be as follows:

```bash
cd ~/nginx
./configure \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    # other parameters passed to ./configure \
    --add-module=./ngx_tcpwrappers
make
sudo make install
```

# Module Configuration

Configuration directives:

* **tcpwrappers**
  * **Syntax:** `tcpwrappers [on|off]`
  * **Default:** `tcpwrappers off`
  * **Context:** http, server, location, limit_except
  * **Description:** allows or disallows the use of TCP Wrappers for the access control.
`tcpwrappers off` turns off TCP Wrappers completely; this can be useful to avoid performance penalties.
* **tcpwrappers_daemon**
  * **Syntax:** `tcpwrappers_daemon name`
  * **Default:** `tcpwrappers_daemon nginx`
  * **Context:** http, server, location, limit_except
  * **Description:** specifies the name of the daemon used in `/etc/hosts.{allow,deny}` to identify the process.
* **tcpwrappers_thorough**
  * **Syntax:** `tcpwrappers_thorough [on|off]`
  * **Default:** `tcpwrappers_thorough off`
  * **Context:** http, server, location, limit_except
  * **Description:** controls thoroughness of the verification.
With `tcpwrappers_thorough off` [hosts_ctl(3)](http://linux.die.net/man/3/hosts_ctl) is used; access check uses only the IP address.
With `tcpwrappers_thorough on` [hosts_access(3)](http://linux.die.net/man/3/hosts_access) is used; access check uses the IP address, user name (if available),
reverse DNS. This check is more thorough but the price is a DNS query to resolve the IP address.

# Further Reading
* [hosts_access(5) manual](http://linux.die.net/man/5/hosts_access)
