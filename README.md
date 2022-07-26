# gluu_openid_python

This python script will allow you to use dynamic client registration to register a client with your Gluu server, optionally using a [JSON Web Key Set](https://datatracker.ietf.org/doc/html/rfc7517#section-5) file to allow for JWK authentication via OpenID. 

## Requirements
- Python3
- pip3
- (Optional) A JWKS file containing a JSON Web Key Set. The script expects `client-key.jwks` by default.

## Setup
1. Clone the repository, and navigate to it.
2. Set up a virtual python environment: `python -m venv venv`
3. And activate it: `source venv/bin/activate`
4. Install requirements: `pip install -r requirements.txt`
5. Run the script: `python scim_client`