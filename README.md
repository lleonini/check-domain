# Check Domain - XD

Check Domain is an HTTP/HTTPS domain/url checking tool that presents an overview
of servers settings, certificates, headers, redirections, CNAME/IP, CDN...

It was initially developed to compare results between origin servers and AKAMAI
production/staging networks without having to edit /etc/hosts.

Using `--commands`, one can see all the wrapped command lines and modify
them to suit particular needs.

## Install

- Packages: ruby 1.8+, curl 7.19+
- bundle install

## Features

- Integrated host spoofing (no /etc/host dependency)
- Highlight:
	-	IPs (public / local)
	-	CNAME
	- HTTP response code
	-	Server
	- Headers
	-	Redirections (loop detection)
	-	SSL, HSTS
	-	Content consolidation: length, encoding, compression
	-	Caching consolidation
- CDN:
  - Detection of AKAMAI, CloudFront, CloudFlare, MaxCDN and Fastly
	- AKAMAI:
		- Debug headers
		- Staging and production networks
		- Error reference number
		- Caching information
- SSL certificates checking
- Performance indicators:
	- Total time
	- Download speed
- Support mutiple hosts for one domain (in config file)
- Parallel command execution for faster results

## Usage

`alias xd='./xd.rb'`

## Examples

Simple domain check on default host (not using config):

`xd www.ibm.com`

Check an URL (not using config):

`xd https://www.ibm.com/hello`

You can also use name/aliases from config file:

`xd adobe ibm`

Chain as many as you want. You can also mix elements from the config file and
URLs/domains.

Finally, if you want to list all domains in config just do:

`xd -l`

And to check all of them:

`xd --all`

## Config file

Example of simple config file:

```json
{
	"domains": [
		{
			"alias": "adobe",
			"name": "www.adobe.com",
			"content": "Creative, marketing and document management solutions",
			"hosts": [
				"test.edgekey-staging.net",
				"test.edgekey.net"
			]
		},
		{
			"alias": "ibm bigblue",
			"name": "www.ibm.com",
			"content": "IBM Corp. 2016",
			"ssl": true
		},
		{
			"alias": "kodak",
			"name": "www.kodak.com"
		},
		{
			"alias": "kayak",
			"name": "www.kayak.com"
		},
		{"name": "www.zendesk.com"}
	]
}

```

Default config file location: $HOME/.xd.json
