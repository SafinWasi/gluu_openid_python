import json
import sys
import requests


class ScimClient:
    """An implementation of a simple client application to create an OpenID user on Gluu."""

    def __init__(self, hostName, certFile):
        self.HOSTNAME = hostName
        self.CERT = certFile
        self.JWKS_ENDPOINT = hostName + "oxauth/restv1/jwks"
        self.TOKEN_ENDPOINT = None
        self.OPENID_CONFIGS = hostName + ".well-known/openid-configuration"

        self.jwks = None
        self.client_id = None
        self.client_secret = None

    def get_jwks(self, file="client-key.jwks"):
        """Reads a JWKS file and loads the JSON web key set."""
        with open(file, 'r') as f:
            data = json.loads(f.read())
        self.jwks = data

    def get_client(self):
        """
        Sends a POST request to the server for dynamic client registration.
        The client will optionally use private_key_jwt for authentication if
        ScimClient.get_jwks() was called.
        """
        r = requests.get(self.OPENID_CONFIGS, verify=self.CERT)
        if r.status_code != 200:
            print("Request returned", r.status_code)
        else:
            data = r.json()
            reg = data["registration_endpoint"]
            self.TOKEN_ENDPOINT = data["token_endpoint"]
            print("Enter a name for the new client: ", end="")
            client_name = input()
            payload = {
                "application_type": "native",
                "redirect_uris": [self.HOSTNAME + "callback"],
                "client_name": client_name,
                "grant_types": ["client_credentials"]
            }
            if self.jwks is not None:
                payload['jwks'] = self.jwks
                payload["token_endpoint_auth_method"] = "private_key_jwt"

            
            r2 = requests.post(reg, json=payload, verify=self.CERT)
            if r2.status_code == 200:
                client_id = r2.json()["client_id"]
                client_secret = r2.json()["client_secret"]
                output = {"client_id": client_id, "client_secret": client_secret}
                print("Writing client ID and secret to client.json...")
                with open("client.json", "w") as f:
                    f.write(json.dumps(output, indent=4))
                print(json.dumps(r2.json(), indent=4))
            else:
                print("Returned status code", r2.status_code)
                print(r2.content)

    def read_client(self, file="client.json"):
        """Reads an existing JSON file for client configuration."""
        with open(file, "r") as f:
            data = json.loads(f.read())
        self.client_id = data["client_id"]
        self.client_secret = data["client_secret"]


if len(sys.argv) < 2:
    print("Usage: python scim_client.py <hostname> <path to host's cacert> <path to your Java Ketstore file>")
    exit()



testClient = ScimClient(
    sys.argv[1], sys.argv[2]
)
testClient.get_jwks(sys.argv[3])
testClient.get_client()