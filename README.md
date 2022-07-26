# gluu_openid_python

This python script will allow you to use [Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html) to register a client with your Gluu server, optionally using a [JSON Web Key Set](https://datatracker.ietf.org/doc/html/rfc7517#section-5) file to allow for JWK authentication via OpenID. 

## Requirements
- Python3
- pip3
- The SSL certificate from your Gluu server, which can be found at `Configuration` > `Certificates` > `HTTPD SSL` and clicking `Download`. The script expects `httpd.crt` by default. 
- (Optional) A JWKS file containing a JSON Web Key Set. The script expects `client-key.jwks` by default.

## Setup
1. Clone the repository, and navigate to it.
2. Set up a virtual python environment: `python -m venv venv`
3. And activate it: `source venv/bin/activate`
4. Install requirements: `pip install -r requirements.txt`
5. Run the script: `python gluu_client_reg.py <hostname> <path to host's SSL certificate> <path to your JWKS file>`
6. Enter a name for your new client when prompted. Remember this; you will need it later.
7. If the script runs successfully, the new client ID and secret will be saved to `client.json`. **Do not** share this information.

## Notes
The script is meant to be run directly using Python; however, you may use it as a module in your own programs if you wish.

## References
- [Gluu 4.4 Documentation](https://gluu.org/docs/gluu-server/4.4/)
- [JWK Specification](https://datatracker.ietf.org/doc/html/rfc7517)