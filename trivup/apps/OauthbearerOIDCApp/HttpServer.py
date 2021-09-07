from http.server import BaseHTTPRequestHandler, HTTPServer
import jwt
import datetime

class WebServerHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
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
        return

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
        if self.path.endswith("/retrieve"):

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            if not self.headers['Content-Type']: {
                self.send_error(404, 'Content-Type field is required')
            }
            if not self.headers['cache-control']: {
                self.send_error(404, 'cache-control field is required')
            }

            if not self.headers['authorization']: {
                self.send_error(404, 'authorization field is required')
            }

            if not self.headers['Content-Length']: {
                self.send_error(404, 'Content-Length field is required')
            }

            if not post_data:
                self.send_error(404, 'method and scope fields are required in data')
            
            payloads = {"exp": datetime.datetime.utcnow() + \
                               datetime.timedelta(seconds=30)}

            encoded_jwt = jwt.encode(payloads, "secret", algorithm="HS256", 
                                     headers={"kid": self.headers['authorization']})
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(encoded_jwt.encode())
        else:
            self.send_error(404, 'URL is not valid: %s' % self.path)

def main():
    try:
        port = 8000
        server = HTTPServer(('', port), WebServerHandler)
        print ("Web Server running on port %s" % port)
        server.serve_forever()
    except KeyboardInterrupt:
        print (" ^C entered, stopping web server....")
        server.socket.close()

if __name__ == '__main__':
    main()