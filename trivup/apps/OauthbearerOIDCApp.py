#!/usr/bin/env python
#

# Copyright (c) 2021, Magnus Edenhill
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from trivup import trivup
from http.server import BaseHTTPRequestHandler, HTTPServer
import jwt
import datetime
import json
import argparse
import requests
from Crypto.PublicKey import RSA


class WebServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text')
        self.end_headers()
        message = "HTTP server for OAuth\n"
        message += "Example for token retrieval:\n"
        message += 'curl \
        -X POST \
        --url localhost:8000/retrieve \
        -H "Accept: application/json" \
        -H "Authorization: Basic LW4gYWJjMTIzOlMzY3IzdCEK" \
        -H "Cache-Control: no-cache" \
        -d "method=oidc,scope=test-scope"'
        self.wfile.write(message.encode())
        print(message)

    def generate_token(self, payloads, authorization):
        pass

    def generate_valid_token_for_client(self):
        """
        Example usage:
        curl \
        -X POST \
        --url localhost:8000/retrieve \
        -H "Accept: application/json" \
        -H "Authorization: Basic LW4gYWJjMTIzOlMzY3IzdCEK" \
        -H "Cache-Control: no-cache" \
        -d "method=oidc,scope=test-scope"
        """
        if self.headers.get('Content-Length', None) is None:
            self.send_error(404, 'Content-Length field is required')
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        if self.headers.get('Cache-Control', None) != "no-cache":
            self.send_error(404, 'Cache-Control should be "no-cache"')
            return

        if self.headers.get('Authorization', None) is None:
            self.send_error(404, 'Authorization field is required')
            return

        if self.headers.get('Accept', None) != "application/json":
            self.send_error(404, 'Accept field should be "application/json"')
            return

        if post_data is None:
            self.send_error(404,
                            'method and scope fields are required in data')
            return

        payloads = {"exp": datetime.datetime.utcnow() +
                    datetime.timedelta(seconds=300)}

        encoded_jwt = jwt.encode(payloads,
                                 self.headers['authorization'],
                                 algorithm="HS256")
        self.send_response(200)
        self.send_header('Content-type', 'text')
        self.end_headers()
        messages = {"access_token": encoded_jwt}
        self.wfile.write(json.dumps(messages, indent=4).encode())

    def response_to_broker(self):
        new_key = RSA.generate(2048, e=65537)
        public_key = new_key.publickey().exportKey("PEM")

        self.send_response(200)
        self.send_header('Content-type', 'text')
        self.end_headers()
        self.wfile.write(public_key.encode())

    def generate_badformat_token_for_client(self):
        pass

    def generate_unverifiable_token_for_client(self):
        pass

    def do_POST(self):
        if self.path.endswith("/retrieve"):
            self.generate_valid_token_for_client()
        elif self.path.endswith("/keys"):
            self.response_to_broker()
        elif self.path.endswith("/retrieve/badformat"):
            self.generate_badformat_token_for_client()
        elif self.path.endswith("/retrieve/unverifiable"):
            self.generate_unverifiable_token_for_client()
        else:
            self.send_error(404, 'URL is not valid: %s' % self.path)


class OauthbearerOIDCHttpServer():
    def run_http_server(self, port):
        server = HTTPServer(('', port), WebServerHandler)
        server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Trivup Oauthbearer OIDC \
                                                  HTTP server')
    parser.add_argument('--port', type=int, dest='port',
                        default=False, required=True,
                        help='Port at which OauthbearerOIDCApp \
                              should be bound')
    args = parser.parse_args()
    http_server = OauthbearerOIDCHttpServer()
    http_server.run_http_server(args.port)


class OauthbearerOIDCApp (trivup.App):
    """ Oauth/OIDC app, run a http server """
    def __init__(self, cluster, conf=None, on=None):
        """
        @param cluster     Current cluster.
        @param conf        Configuration dict.
               port        Port at which OauthbearerOIDCApp should be bound
                           (optional). A (random) free port will be chosen
                           otherwise.
        @param on          Node name to run on.
        """
        super(OauthbearerOIDCApp, self).__init__(cluster, conf=conf, on=on)
        self.conf['port'] = trivup.TcpPortAllocator(self.cluster).next(
            self, port_base=self.conf.get('port', None))
        self.conf['url'] = 'http://localhost:%d' % self.conf['port']

    def start_cmd(self):
        return "python -m trivup.apps.OauthbearerOIDCApp --port %d" \
               % self.conf['port']

    def operational(self):
        self.dbg('Checking if %s is operational' % self.get('url'))
        try:
            r = requests.get(self.get('url'))
            if r.status_code == 200:
                return True
            raise Exception('status_code %d' % r.status_code)
        except Exception as e:
            self.dbg('%s check failed: %s' % (self.get('url'), e))
            return False

    def deploy(self):
        pass
