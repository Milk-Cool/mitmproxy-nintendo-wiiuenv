from mitmproxy import http, ctx
from os.path import expanduser
import os


DEVICE_ID = None
SERIAL_NUMBER = None
SYSTEM_VERSION = None
REGION_ID = None
COUNTRY_NAME = None
LANGUAGE = None
USERNAME = None
PASSWORD = None
CERT = None


class PretendoAddon:
    def running(_self):
        ctx.log.info("Building Inkay...")
        certf = open(expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem"), "r")
        cert = certf.read()
        certf.close()

        inkaycertf = open(os.path.join(os.getcwd(), "Inkay", "data", "ca.pem"), "w")
        inkaycertf.write(cert)
        inkaycertf.close()

        os.system("docker build Inkay -t inkay-build")
        os.system(f"docker run -it --rm -v {os.path.join(os.getcwd(), "Inkay")}:/app -w /app inkay-build")

        ctx.log.info("Built Inkay! Built module can be found at Inkay/Inkay-pretendo.wps")
    
    def load(self, loader) -> None:
        loader.add_option(
            name="pretendo_redirect",
            typespec=bool,
            default=True,
            help="Redirect all requests from Nintendo to Pretendo",
        )

        loader.add_option(
            name="pretendo_host",
            typespec=str,
            default="",
            help="Host to send Pretendo requests to (keeps the original host in the Host header)",
        )

        loader.add_option(
            name="pretendo_host_port",
            typespec=int,
            default=80,
            help="Port to send Pretendo requests to (only applies if pretendo_host is set)",
        )

        loader.add_option(
            name="pretendo_http",
            typespec=bool,
            default=False,
            help="Sets Pretendo requests to HTTP (only applies if pretendo_host is set)",
        )

    def request(self, flow: http.HTTPFlow) -> None:
        global DEVICE_ID, SERIAL_NUMBER, SYSTEM_VERSION
        global REGION_ID, COUNTRY_NAME, LANGUAGE
        global CERT, USERNAME, PASSWORD

        h = flow.request.headers
        if "X-Nintendo-Device-ID" in h:
            DEVICE_ID = h["X-Nintendo-Device-ID"]
        if "X-Nintendo-Serial-Number" in h:
            SERIAL_NUMBER = h["X-Nintendo-Serial-Number"]
        if "X-Nintendo-System-Version" in h:
            SYSTEM_VERSION = hex(int(h["X-Nintendo-System-Version"], 16))[2:]
        if "X-Nintendo-Region" in h:
            REGION_ID = int(h["X-Nintendo-Region"])
        if "X-Nintendo-Country" in h:
            COUNTRY_NAME = h["X-Nintendo-Country"]
        if "Accept-Language" in h:
            LANGUAGE = h["Accept-Language"]
        if "X-Nintendo-Device-Cert" in h:
            CERT = h["X-Nintendo-Device-Cert"]

        b = flow.request.urlencoded_form
        if len(b.fields) == 0:
            return
        if "user_id" in b:
            USERNAME = b["user_id"]
        if "password" in b:
            PASSWORD = b["password"]
        
        if ctx.options.pretendo_redirect:
            if "nintendo.net" in flow.request.pretty_host:
                flow.request.host = flow.request.pretty_host.replace(
                    "nintendo.net", "pretendo.cc"
                )
            elif "nintendowifi.net" in flow.request.pretty_host:
                flow.request.host = flow.request.pretty_host.replace(
                    "nintendowifi.net", "pretendo.cc"
                )

            if ctx.options.pretendo_host and (
                "pretendo.cc" in flow.request.pretty_host
                or "pretendo.network" in flow.request.pretty_host
                or "pretendo-cdn.b-cdn.net" in flow.request.pretty_host
            ):
                original_host = flow.request.host_header
                flow.request.host = ctx.options.pretendo_host
                flow.request.port = ctx.options.pretendo_host_port
                flow.request.host_header = original_host

                if ctx.options.pretendo_http:
                    flow.request.scheme = "http"

    def done(_self):
        global DEVICE_ID, SERIAL_NUMBER, SYSTEM_VERSION
        global REGION_ID, COUNTRY_NAME, LANGUAGE
        global CERT, USERNAME, PASSWORD

        env = open("wiiu.env", "w")
        env.write(f"""DEVICE_ID={DEVICE_ID}
SERIAL_NUMBER={SERIAL_NUMBER}
SYSTEM_VERSION={SYSTEM_VERSION}
REGION_ID={REGION_ID}
COUNTRY_NAME={COUNTRY_NAME}
LANGUAGE={LANGUAGE}
CERT={CERT}
USERNAME={USERNAME}
PASSWORD={PASSWORD}""")
        env.close()

        envwin = open("wiiu.env", "w")
        envwin.write(f"""set DEVICE_ID={DEVICE_ID}
set SERIAL_NUMBER={SERIAL_NUMBER}
set SYSTEM_VERSION={SYSTEM_VERSION}
set REGION_ID={REGION_ID}
set COUNTRY_NAME={COUNTRY_NAME}
set LANGUAGE={LANGUAGE}
set CERT={CERT}
set USERNAME={USERNAME}
set PASSWORD={PASSWORD}""")
        envwin.close()

        envlinux = open("wiiu.env", "w")
        envlinux.write(f"""export DEVICE_ID={DEVICE_ID}
export SERIAL_NUMBER={SERIAL_NUMBER}
export SYSTEM_VERSION={SYSTEM_VERSION}
export REGION_ID={REGION_ID}
export COUNTRY_NAME={COUNTRY_NAME}
export LANGUAGE={LANGUAGE}
export CERT={CERT}
export USERNAME={USERNAME}
export PASSWORD={PASSWORD}""")
        envlinux.close()


addons = [PretendoAddon()]
