import argparse
import logging
import os
import subprocess
import sys

import jinja2
import yaml


CMD = "/usr/bin/openssl"

base_path = os.path.dirname(os.path.realpath(__file__))
VERSION = "1"


logger = logging.getLogger()


def openssl(args, input=None, env=None):
    process = subprocess.Popen(
        [CMD] + args,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    stdout, stderr = [s.decode("utf-8").strip() for s in process.communicate(input=input)]
    logger.debug(f"{stdout} {stderr}")
    if process.returncode != 0:
        raise Exception(f"Error[{process.returncode}]:\n{stdout}\n\n{stderr}")
    return stdout


def generate_openssl_config(name, root_dir, conf, templates_dir="."):
    tpl_name = conf.get("tpl_name")
    if tpl_name:
        searchpath = conf.get("tpl_path", templates_dir)
        template = jinja2.Environment(
            loader=jinja2.FileSystemLoader(searchpath=searchpath)
        ).get_template(tpl_name)
        params = {"name": name, "root_dir": root_dir}
        fpath = conf.get("path", os.path.join(root_dir, f"{name}.conf"))
        create_file_if_not_exists(fpath, template.render(**params).encode("utf-8"))
        conf["path"] = fpath


def create_file_if_not_exists(fpath, data=None):
    if not os.path.exists(fpath):
        with open(fpath, "wb") as fobj:
            if data:
                try:
                    data = data.encode("utf-8")
                except AttributeError:
                    pass
                fobj.write(data)


def initialize_directories(root_dir, serial=None, clrnumber=None):
    dirs = dict(
        (directory, os.path.join(root_dir, directory))
        for directory in ["certs", "crl", "requests", "newcerts", "private"]
    )
    os.makedirs(root_dir, exist_ok=True)
    for directory, path in dirs.items():
        os.makedirs(path, exist_ok=True)

    os.chmod(dirs["private"], 0o700)

    create_file_if_not_exists(os.path.join(root_dir, "index.txt"))
    create_file_if_not_exists(os.path.join(root_dir, "index.txt.attr"))
    create_file_if_not_exists(os.path.join(root_dir, "serial"), serial)
    create_file_if_not_exists(os.path.join(root_dir, "crlnumber"), clrnumber)

    return dirs


def create_private_key(name, private_dir, settings):
    fpath = os.path.join(private_dir, f"{name}.key.pem")
    if not os.path.exists(fpath):
        cipher = settings.get("cipher", "aes256")
        numbits = settings.get("numbits", 4096)
        password = settings.get("password")
        args = ["genrsa", f"-{cipher}", "-out", fpath]
        args = args + (["-passout", f"pass:{password}"] if password else [])
        args = args + [f"{numbits}"]

        openssl(args)
        os.chmod(fpath, 0o400)
    logger.debug(f"Created private key {fpath}")
    return fpath


def create_certificate(name, conf_file, certs_dir, key_file, key_password, settings):
    fpath = os.path.join(certs_dir, f"{name}.cert.pem")
    if not os.path.exists(fpath):
        subject = settings["subject"]
        cipher = settings.get("cipher", "sha256")
        days = settings.get("days", "7300")
        extensions = settings.get("extensions")
        args = ["req", "-new", "-x509", "-config", conf_file, "-key", key_file]
        args = args + ["-out", fpath, "-days", f"{days}", f"-{cipher}", "-subj", subject]
        args = args + (["-passin", f"pass:{key_password}"] if key_password else [])
        args = args + (["-extensions", extensions] if extensions else [])

        openssl(args)
        os.chmod(fpath, 0o444)

    logger.debug(openssl(["x509", "-noout", "-text", "-in", fpath]))
    logger.debug(f"Created certifcate {fpath}")
    return fpath


def create_certificate_request(name, conf_file, requests_dir, key_file, key_password, settings):
    fpath = os.path.join(requests_dir, f"{name}.csr.pem")
    if not os.path.exists(fpath):
        subject = settings["subject"]
        cipher = settings.get("cipher", "sha256")
        args = ["req", "-config", conf_file, "-new", f"-{cipher}", "-key", key_file]
        args = args + ["-out", fpath, "-subj", subject]
        args = args + (["-passin", f"pass:{key_password}"] if key_password else [])
        openssl(args)

    logger.debug(f"Created Certificate Signing Request {fpath}")
    return fpath


def create_signed_certificate(
    name, ca_conf_file, ca_cert_file, ca_key_password, certs_dir, requests_file, settings
):
    fpath = os.path.join(certs_dir, f"{name}.cert.pem")
    if not os.path.exists(fpath):
        cipher = settings["cipher"]
        days = settings["days"]
        extensions = settings["extensions"]
        args = ["ca", "-batch", "-config", ca_conf_file]
        args = args + ["-extensions", extensions, "-days", f"{days}"]
        args = args + (["-passin", f"pass:{ca_key_password}"] if ca_key_password else [])
        args = args + ["-notext", "-md", cipher, "-in", requests_file, "-out", fpath]

        openssl(args)
        os.chmod(fpath, 0o444)
    openssl(["x509", "-noout", "-text", "-in", fpath])
    # openssl(['verify', '-CAfile', ca_cert_file, fpath])

    if settings.get("bundle"):
        chain_fpath = os.path.join(certs_dir, f"{name}-chain.cert.pem")
        if not os.path.exists(chain_fpath):
            with open(chain_fpath, "wb") as fobj:
                for cert_file in [ca_cert_file, fpath]:
                    with open(cert_file, "rb") as infile:
                        fobj.write(infile.read())
            os.chmod(chain_fpath, 0o444)
        logger.debug(f"Chain file {chain_fpath} created")
        # openssl(['verify', '-CAfile', chain_fpath, fpath])
    logger.debug(f"Signed certificate {fpath} created")
    return fpath


class Exporter:
    @classmethod
    def pfx(
        cls, name, certs_dir, cert_file, key_file, key_password, pfx_password, ca_cert_file=None
    ):
        """
        openssl pkcs12 -export -in certificate.crt -inkey privatekey.key -out certificate.pfx
        openssl pkcs12 -export -in certificate.crt -inkey privatekey.key -out certificate.pfx
            -certfile CAcert.crt
        """
        fpath = os.path.join(certs_dir, f"{name}.pfx")
        if not os.path.exists(fpath):
            args = ["pkcs12", "-export"]
            args = args + ["-in", cert_file, "-inkey", key_file, "-out", fpath]
            args = args + (["-passin", f"pass:{key_password}"] if key_password else [])
            args = args + (["-passout", f"pass:{pfx_password}"] if pfx_password else [])
            args = args + (["-certfile", ca_cert_file] if ca_cert_file else [])
            openssl(args)

        logger.debug(f"Exported certificate in PFX format to {fpath}")

    @classmethod
    def der(cls, name, certs_dir, cert_file, key_file, key_password, ca_cert_file=None):
        """
        openssl x509 -outform der -in certificate.pem -out certificate.der
        """

    @classmethod
    def pkc8(cls, name, certs_dir, cert_file, key_file, key_password, ca_cert_file=None):
        """
        openssl pkcs8 -topk8 -inform PEM -outform DER -in filename -out filename -nocrypt
        """


def build(configuration, templates_dir):
    version = configuration.pop("version")
    logger.debug(f"conf version: {version}")
    for cert, settings in configuration.items():
        logger.debug(f"Generating {cert} Certificate")
        settings.setdefault("keys", {})
        settings.setdefault("certs", {})
        settings.setdefault("requests", {})

        settings["dirs"] = initialize_directories(
            settings["root_dir"], serial=settings.get("serial"), clrnumber=settings.get("clrnumber")
        )

        generate_openssl_config(cert, settings["root_dir"], settings["conf"], templates_dir)

        if settings.get("key"):
            settings["keys"][cert] = create_private_key(
                cert, settings["dirs"]["private"], settings["key"]
            )

        if settings.get("cert"):
            settings["certs"][cert] = create_certificate(
                cert,
                settings["conf"]["path"],
                settings["dirs"]["certs"],
                settings["keys"][cert],
                settings["key"].get("password"),
                settings["cert"],
            )

        if settings.get("csr"):
            settings["requests"][cert] = create_certificate_request(
                cert,
                settings["conf"]["path"],
                settings["dirs"]["requests"],
                settings["keys"][cert],
                settings["key"].get("password"),
                settings["csr"],
            )

        if settings.get("from"):
            ca = settings["from"]["ca"]
            settings["certs"][cert] = create_signed_certificate(
                cert,
                configuration[ca]["conf"]["path"],
                configuration[ca]["certs"][ca],
                configuration[ca]["key"].get("password"),
                settings["dirs"]["certs"],
                settings["requests"][cert],
                settings["from"],
            )

        if settings.get("export"):
            for ext in settings["export"]:
                try:
                    exporter = getattr(Exporter, ext)
                    ca_cert_file = configuration[ca]["certs"][ca] if settings.get("from") else None

                    exporter(
                        cert,
                        settings["dirs"]["certs"],
                        settings["certs"][cert],
                        settings["keys"][cert],
                        settings["key"].get("password"),
                        settings["export"].get("password"),
                        ca_cert_file,
                    )
                except AttributeError:
                    logger.error(f"Unsupported export format: ext")


def cli():
    parser = argparse.ArgumentParser(description="TLSTool simplifies generating TLS certs")
    parser.add_argument("-c", "--conf", type=str, help="TLSTool config file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    parser.add_argument(
        "-t",
        "--templates-dir",
        type=str,
        help="Specify folder where openssl config templates are stored.",
        default="./templates",
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(stream=sys.stdout, level=log_level)

    with open(args.conf) as fobj:
        conf = yaml.load(fobj, Loader=yaml.Loader)
    build(conf, args.templates_dir)


if __name__ == "__main__":
    cli()
