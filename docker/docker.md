ChopShop Dockerfile
==================

This repository contains a **Dockerfile** of [ChopShop](https://github.com/MITRECND/chopshop) for [Docker](https://www.docker.io/)'s [trusted build](https://index.docker.io/u/blacktop/chopshop/) published to the public [Docker Registry](https://index.docker.io/).

### Dependencies
* [debian:jessie](https://index.docker.io/_/debian/)

### Image Size
[![](https://badge.imagelayers.io/blacktop/chopshop:latest.svg)](https://imagelayers.io/?images=blacktop/chopshop:latest 'Get your own badge on imagelayers.io')

### Image Tags
```bash
$ docker images

REPOSITORY          TAG                 IMAGE ID           VIRTUAL SIZE
blacktop/chopshop   latest              1df35766838d       262.3 MB
```

### Installation

1. Install [Docker](://www.docker.io/).

2. Download [trusted build](://index.docker.io/u/blacktop/chopshop/) from public [Docker Registry](://index.docker.io/): `docker pull blacktop/chopshop`

#### Alternatively, build an image from Dockerfile
```bash
$ docker build -t blacktop/chopshop github.com/blacktop/docker-chopshop
```
### Usage
```bash
$ docker run -i -t -v /path/to/folder/pcap:/pcap:rw blacktop/chopshop -f my.pcap "http | http_extractor"
```
#### Output:
```
{
  "request": {
    "protocol": "HTTP/1.1",
    "uri": {
      "path": "/capabilities/cybersecurity/overview/cybersecurity-blog/an-introduction-to-chopshop-network-protocol",
      "port_number": -1
    },
    "headers": {
      "Host": "www.mitre.org",
      "Connection": "Keep-Alive",
      "Accept": "*/*",
      "User-Agent": "Wget/1.15 (linux-gnu)"
    },
    "method": "GET"
  },
  "response": {
    "status": 200,
    "body": "base64data",
    "body_encoding": "base64",
    "body_hash": "737203915c5f14da7f8b9c057678adfe",
    "headers": {
      "X-Request-ID": "v-334516c-565b-1224-b459-1232345469ec",
      "X-Varnish": "5670865685 1569753878",
      "X-Drupal-Cache": "MISS",
      "X-Cache": "HIT",
      "Content-Language": "en",
      "Transfer-Encoding": "chunked",
      "Age": "2342",
      "Expires": "Sun, 19 Nov 1978 05:00:00 GMT",
      "Vary": "Cookie,Accept-Encoding",
      "X-AH-Environment": "prod",
      "Server": "nginx",
      "Last-Modified": "Mon, 11 Oct 2014 01:49:48 +0000",
      "Connection": "keep-alive",
      "Etag": "14145343481-1",
      "Link": "<http://www.mitre.org/node/14985>; rel=shortlink,<http://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/an-introduction-to-chopshop-network-protocol>; rel=canonical",
      "Cache-Control": "public, max-age=3600",
      "Date": "Mon, 13 Oct 2014 02:28:50 GMT",
      "X-Cache-Hits": "4",
      "Content-Type": "text/html; charset=utf-8",
      "Via": "1.1 varnish",
      "X-Generator": "Drupal 7 (http://drupal.org)"
    }
  }
}
```

### To Run on OSX
 - Install [Homebrew](http://brew.sh)

```bash
$ brew install caskroom/cask/brew-cask
$ brew cask install virtualbox
$ brew install docker
$ brew install docker-machine
$ docker-machine create --driver virtualbox dev
$ eval $(docker-machine env dev)
```
Add the following to your bash or zsh profile

```bash
alias chopshop='docker run -it --rm -v `pwd`:/pcap:rw blacktop/chopshop $@'
```
#### Usage

```bash
chopshop -f malware.pcap "(dns, icmp) | malware_detector"
```

### Todo
- [x] Install/Run ChopShop
- [ ] Add MongoDB
