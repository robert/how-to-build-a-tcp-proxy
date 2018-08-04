# How to make a TCP proxy

This is the code from my series on how to build a TCP proxy:

* [How to build a TCP proxy #1: Intro](https://robertheaton.com/2018/08/31/how-to-build-a-tcp-proxy-1/).
* [How to build a TCP proxy #2: Fake DNS Server](https://robertheaton.com/2018/08/31/how-to-build-a-tcp-proxy-2/).
* [How to build a TCP proxy #3: Proxy Server](https://robertheaton.com/2018/08/31/how-to-build-a-tcp-proxy-3/).
* [How to build a TCP proxy #3: Fake Certificate Authority](https://robertheaton.com/2018/08/31/how-to-build-a-tcp-proxy-4/).

## Installation

1. Clone this repo
2. In the repo directory, make a new virtualenv using `virtualenv vendor`
3. Activate it using `source vendor/bin/activate`
4. Install requirements to the virtualenv using `pip install -r requirements.txt`
5. Whenever you want to run the code, activate the virtualenv by running `source vendor/bin/activate` again

## Usage

### Fake DNS Server

Set your phone's DNS server to be the local IP of your laptop. Then run:

```
sudo python fake_dns_server.py
```

For lots more detail, see [How to build a TCP proxy #2: Fake DNS Server](https://robertheaton.com/2018/08/31/how-to-build-a-tcp-proxy-2/).

### Non-TLS TCP proxy

Set the DNS Spoofer running, then:

```
sudo python tcp_proxy.py
```

For lots more detail, see [How to build a TCP proxy #3: Proxy Server](https://robertheaton.com/2018/08/31/how-to-build-a-tcp-proxy-3/).

### TLS TCP proxy

Set the DNS Spoofer running, then:

```
sudo python tls_tcp_proxy.py
```

For lots more detail, see [How to build a TCP proxy #4: Proxy Server](https://robertheaton.com/2018/08/31/how-to-build-a-tcp-proxy-4/).
