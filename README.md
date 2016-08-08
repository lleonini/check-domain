# Check Domain - XD

Check Domain is an HTTP/HTTPS domain tool that presents an overview of servers
settings, certificates, headers, redirections, CNAME/IP, CDN...

It was initially developped to compare results between origin servers and AKAMAI
production and staging networks without having to edit /etc/hosts.

By design, this is mostly a curl wrapper and using `--commands` you will get the
command lines that you can then modify to suit your needs.

## Install

- Packages: ruby 1.8+, curl 7.19+, openssl
- bundle install

## Features

- Integrated host spoofing:
		- no need to edit /etc/hosts
		- output is independent of /etc/hosts (except to show local IP if one)
- Show CNAME, IPs and CDN:
	- CDN support: AKAMAI, CloudFront, CloudFlare, MaxCDN, Fastly
	- AKAMAI: debug headers, detection of staging and production networks
- Support mutiple vhosts for one domain (in config file)
- SSL certificate check
- Compression check
- Content check
- Parallel command execution for faster results
- Highlighted output
- Follow HTTP redirections
- Performance indicators
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
