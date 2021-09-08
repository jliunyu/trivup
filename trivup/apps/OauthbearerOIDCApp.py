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
        -H "accept: application/json" \
        -H "authorization: Basic LW4gYWJjMTIzOlMzY3IzdCEK" \
        -H "cache-control: no-cache" \
        -H "content-type: application/x-www-form-urlencoded" \
        -d "method=oidc,scope=test-scope"'
        self.wfile.write(message.encode())
        print (message)

    def do_POST(self):
        '''
        Example usage:
        curl \
        -X POST \
        --url localhost:8000/retrieve \
        -H "accept: application/json" \
        -H "authorization: Basic LW4gYWJjMTIzOlMzY3IzdCEK" \
        -H "cache-control: no-cache" \
        -H "content-type: application/x-www-form-urlencoded" \
        -d "method=oidc,scope=test-scope"
        '''
        if not self.path.endswith("/retrieve"):
            self.send_error(404, 'URL is not valid: %s' % self.path)
            return

        if self.headers.get('Content-Length', None) is None: {
            self.send_error(404, 'Content-Length field is required')
        }

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        if self.headers.get('Content-Type', None) is None: {
            self.send_error(404, 'Content-Type field is required')
        }

        if self.headers.get('Authorization', None) is None: {
            self.send_error(404, 'Authorization field is required')
        }

        if post_data is None:
            self.send_error(404, 'method and scope fields are required in data')

        payloads = {"exp": datetime.datetime.utcnow() + \
                           datetime.timedelta(seconds=30)}

        encoded_jwt = jwt.encode(payloads, "secret", algorithm="HS256",
                                     headers={"kid": self.headers['authorization']})
        self.send_response(200)
        self.send_header('Content-type', 'text')
        self.end_headers()
        self.wfile.write(encoded_jwt.encode())

class OauthbearerOIDCApp (trivup.App):
    """ Oauth/OIDC app, trigger an http server"""
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

    def start_cmd(self):
        try:
            server = HTTPServer(('', self.conf['port']), WebServerHandler)
            print ("Web Server running on port %s" % self.conf['port'])
            server.serve_forever()
        except KeyboardInterrupt:
            print (" ^C entered, stopping web server....")
            server.socket.close()

    def operational(self):
        pass

    def deploy(self):
        pass
