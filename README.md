# Check Domain - XD

Check Domain is an HTTP/HTTPS domain/url checking tool that presents an overview
of servers settings, certificates, headers, redirections, CNAME/IP, CDN...

It was initially developed to compare results between origin servers and AKAMAI
production/staging networks without having to edit /etc/hosts.

Using `--commands`, one can see all the wrapped command lines and modify
them to suit particular needs.

## Install

- Packages: ruby 1.8+, curl 7.19+, openssl
- bundle install

## Features

- Integrated host spoofing:
		- no need to edit /etc/hosts
		- output is independent of /etc/hosts (except to show local IP if one)
- Show CNAME, IPs and CDN:
	- CDNs: AKAMAI, CloudFront, CloudFlare, MaxCDN, Fastly
	- AKAMAI: debug headers, staging and production networks
- Support mutiple vhosts for one domain (in config file)
- SSL certificate check
- Compression check
- Content check
- Parallel command execution for faster results
- Highlighted output
- Follow HTTP redirections
- Performance indicators
- Behavior independent of HSTS settings
- Use `curl`, `host` and `openssl` behind the scene

### Limitations

- If redirection(s) change the domain, spoofing features will be lost

## Usage

See `./xd.rb --help`

## Examples

TODO

## Config file

TODO syntax

## TODO

- Show HTTP/2 infos
- Support IPv6
