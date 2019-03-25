# TLSTool

TLSTool simplifies creating certificates using a config file. This tool is based entirely from the great [tutorial](https://jamielinux.com/docs/openssl-certificate-authority/introduction.html) written by Jamie Nguyen, that describes how to create Certificate Authorities (CA), Intermediate CAs, server and client certificates and describes the process of creating certificates in greater detail. Go read that article if creating certificates is new to you. Many design decisions for this tool came from that tutorial.

## Prerequisuites

* Linux
* Python >3.6
* Openssl

## Installation

* Install from github
  ```bash
  $ python3.6 -m venv venv3 \
      ./venv3/bin/pip install -U pip \
      ./venv3/bin/pip install https://github.com/somerovi/tlstool.git@1.0.0
  ```

* Install from PyPi: Not uploaded there yet

## Usage

```bash
$ ./venv3/bin/tlstool -c mytlstool.yaml --verbose
```

## Config file examples

A config file defines certificates, a hierachy, which openssl config to use and where to output them.

The config structure is as follows:

```yaml
version: '1'

<domain_name>:

  root_dir: "</path/where/to/output>"

  # Defines how to sign this certificate
  from:

    # Specifies the CA that will be used to sign the certificate
    ca: <ca_domain_name>

    # Concatenates certificates into a chain file
    bundle: true

    # Openssl paramters
    cipher: sha256
    days: 7300
    extensions: v3_intermediate_ca

  # Openssl config file
  conf:
    # Use path, if you have an existing openssl template you want to use
    # NOTE: Make sure that root_dir reflects the output path specified in your openssl config
    path: "/path/to/openssl/config"

    # Use the following if you want to use templates. Main use case for templates is customizing the
    # output path and name of the private key.
    # NOTE: In the future template paramters will go in this section
    tpl_name: "jinja2_template_openssl.tpl"
    tpl_path: "/path/to/mytemplates"

  # Private key
  key:
    cipher: aes256
    bits: 4096
    # Leave blank for prompt
    password: 91459

  # Certificate Signing Request
  csr:
    subject: "/C=US/ST=VT/L=Burlington/O=Samir Omerovic/OU=Tech/CN=dev.example.com"
    cipher: sha256

  # Self signed certificate
  cert:
    subject: "/C=US/ST=VT/L=Burlington/O=Samir Omerovic/OU=Tech/CN=example.com"
    cipher: sha256
    days: 7300
    extensions: v3_ca

  # For openssl certificate database and revocation
  serial: "1000"
  clrnumber: "1000"
```

## Openssl config templates

## Todos

* Add certificate validation steps
* Add more formats for exporting
* Use PyOpenssl for portability
* Add more options for openssl and openssl config templates
