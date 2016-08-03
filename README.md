# Check Domain - XD

Check Domain is an HTTP/HTTPS domain tool that presents a quick overview of servers
settings, certificates, headers, redirections, CNAME/IP, CDN...

It was initially developped to compare results between origin servers and AKAMAI
production and staging networks without having to edit /etc/hosts.

By design, this is mostly a curl wrapper and using `--commands` you will get the
command lines that you can then modify to suit your needs.

## Install

- Packages: ruby 1.8+, curl 7.19+, openssl
- bundle install

## Features

- Integrated host spoofing: no need to modify /etc/hosts anymore
- Mutiple vhosts for a domain (in config file)
- SSL certificate checker
- Compression checks
- Content checks
- Show CNAME and IPs
- CDN detection: AKAMAI, CloudFront, CloudFlare, MaxCDN, Fastly
- Parallel command execution for faster results
- Highlighted output
- Show CNAME, public IP and local IP (if you have set one in /etc/hosts)
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
