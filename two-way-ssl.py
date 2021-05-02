import logging, os, re, ssl, OpenSSL
import werkzeug.serving
import psutil    

from config import config
from flask import Flask, g, render_template, request

app = Flask(__name__)

class PeerCertWSGIRequestHandler(werkzeug.serving.WSGIRequestHandler):
    
    # Saving cert in multiple formats to environ
    def make_environ(self):
        environ = super(PeerCertWSGIRequestHandler, self).make_environ()
        x509_binary = self.connection.getpeercert(True)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_binary)
        x509_dict = self.connection.getpeercert(False)
        environ['peercert'] = x509
        environ['peercert_dict'] = x509_dict
        environ['certif'] = str(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT,x509))
        return environ

# Python3 function, would not work with Python2
def get_user_email():
    client_cert = request.environ['certif']
    # Looking for email but we can fetch other details from client cert
    email_reg = re.compile(r"(^.*)(email:.*com)(.*$)")
    user_email = email_reg.match(str(client_cert))
    if user_email :
        user_email = user_email.group(2).split(':')[1]
        return user_email
    return 'no@email.com'

@app.before_request
def before_request():
  g.email = get_user_email()
  if g.email not in config.ALLOWED_USERS:
    logging.info('Incoming request from IP address %s is denied.' % g.email)
    return "Access denied."
  logging.info('Incoming request user %s is allowed.' % g.email)


if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%m/%d/%Y %I:%M:%S %p')
  ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH,
                                   cafile=config.CA)
  ctx.verify_mode = ssl.CERT_REQUIRED
  ctx.load_cert_chain(config.SERVER_CRT, config.SERVER_KEY)
  app.run(debug=True, host='0.0.0.0', ssl_context=ctx,
          port=35672, request_handler=PeerCertWSGIRequestHandler)
