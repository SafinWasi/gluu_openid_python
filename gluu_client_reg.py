import json
import sys
import requests


class GluuClientReg:
    """An implementation of a simple client application to create an OpenID user on Gluu."""

    def __init__(self, host_name:str, cert_file:str):
        """
        Constructor for GluuClientReg.
        host_name: The hostname of the Gluu server.
        cert_file: The SSL certificate file of the Gluu server.
        """
        if host_name[-1] != "/":
            host_name += "/"
        self.host_name = host_name
        self.cert = cert_file
        self.token_endpoint = None
        self.openid_configs = host_name + ".well-known/openid-configuration"

        self.jwks = None
        self.client_id = None
        self.client_secret = None

    def get_jwks(self, file_name:str="client-key.jwks"):
        """
        Reads a JWKS file and loads the JSON web key set.
        file_name: The JWKS file containing your JSON Web Key Set. Defaults to "client-key.jwks"
        """
        with open(file_name, "r") as file:
            data = json.loads(file.read())
        self.jwks = data

    def get_client(self):
        """
        Sends a POST request to the server for dynamic client registration.
        The client will optionally use private_key_jwt for authentication if
        ScimClient.get_jwks() was called. Otherwise, client_secret_basic will 
        be used.
        """
        r = requests.get(self.openid_configs, verify=self.cert)
        if r.status_code != 200:
            print("Request returned", r.status_code)
        else:
            data = r.json()
            reg = data["registration_endpoint"]
            self.token_endpoint = data["token_endpoint"]
            print("Enter a name for the new client: ", end="")
            client_name = input()
            payload = {
                "application_type": "native",
                "redirect_uris": [self.host_name + "callback"],
                "client_name": client_name,
                "grant_types": ["client_credentials"],
            }
            if self.jwks is not None:
                payload["jwks"] = self.jwks
                payload["token_endpoint_auth_method"] = "private_key_jwt"

            r2 = requests.post(reg, json=payload, verify=self.cert)
            if r2.status_code == 200:
                client_id = r2.json()["client_id"]
                client_secret = r2.json()["client_secret"]
                output = {"client_id": client_id, "client_secret": client_secret}
                print("Writing client ID and secret to client.json...")
                with open("client.json", "w") as file:
                    file.write(json.dumps(output, indent=4))
                # print(json.dumps(r2.json(), indent=4))
                print("Write successful.")
            else:
                print("Returned status code", r2.status_code)
                print(r2.content)

    def read_client(self, file_name:str="client.json"):
        """
        Reads an existing JSON file for client configuration.
        file_name: JSON file containing client_id and client_secret. Defaults to "client.json".
        """
        with open(file_name, "r") as file:
            data = json.loads(file.read())
        self.client_id = data["client_id"]
        self.client_secret = data["client_secret"]


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            "Usage: python gluu_client_reg.py <host_name> <path to host's SSL certificate> <path to your Java Keystore file>"
        )
        sys.exit()

    testClient = GluuClientReg(sys.argv[1], sys.argv[2])
    if len(sys.argv) == 4:
        testClient.get_jwks(sys.argv[3])
    testClient.get_client()