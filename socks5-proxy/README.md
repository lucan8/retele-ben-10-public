# DNS tunnel + socks5 proxy

## Description

`client.py` handles browser HTTP requests using the SOCKS5 protocol, forwarding them through a DNS tunnel to `server.py` that runs on a VPS. The DNS server than forwards the request to the actual server the browser is trying to access and forwards the HTTP response back to the client and repeat.

Each TCP connection uses a different thread to handle HTTP data sending and receival from browser/server, but only one thread is used for DNS queries/responses.

To make sure we can send a lot of data a sliding window technique together with packet signatures(md5 hash) are used.

## Limitations

- Data flow is really slow
- Did not test with a real domain yet
- Error handling could be better
- Thread synchronization could be better