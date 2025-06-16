# Using iodine
On the VPS I ran `iodined -f 10.0.0.1 vilgax.crabdance.com` and
got the following output:
```
Opened dns0
Setting IP of dns0 to 10.0.0.1
Setting MTU of dns0 to 1130
Opened IPv4 UDP socket
Opened IPv6 UDP socket
Listening to dns for domain vilgax.crabdance.com
```

Then I ran on the client `sudo iodine -f -r 164.92.244.69 vilgax.crabdance.com`
and got:
```
Enter tunnel password:
Opened dns0
Opened IPv4 UDP socket
Sending DNS queries for vilgax.crabdance.com to 164.92.244.69
Autodetecting DNS query type (use -T to override).
Using DNS type NULL queries
Version ok, both using protocol v 0x00000502. You are user #1
Setting IP of dns0 to 10.0.0.3
Setting MTU of dns0 to 1130
Server tunnel IP is 10.0.0.1
Skipping raw mode
Using EDNS0 extension
Switching upstream to codec Base128
Server switched upstream to codec Base128
No alternative downstream codec available, using default (Raw)
Switching to lazy mode for low-latency
Server switched to lazy mode
Autoprobing max downstream fragment size... (skip with -m fragsize)
768 ok.. 1152 ok.. ...1344 not ok.. ...1248 not ok.. ...1200 not ok.. 1176 ok.. ...1188 not ok.. will use 1176-2=1174
Setting downstream fragment size to max 1174...
Connection setup complete, transmitting data.
```

`ssh -D 1080 root@10.0.0.1`
