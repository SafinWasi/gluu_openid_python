import base64
import json
import sys
import requests
from jose import jws


class GluuClientReg:
    """An implementation of a simple client application to create an OpenID user on Gluu."""

    def __init__(self, settings: dict):
        """
        Constructor for GluuClientReg.
        settings: the settings dictionary loaded from settings.json
        """
        self.settings = settings
        hostname = self.settings["hostname"]
        if hostname[-1] != "/":
            hostname += "/"
        self.settings["hostname"] = hostname
        openid_configs = hostname + ".well-known/openid-configuration"
        self.settings["openid"] = openid_configs
        self.client_id = None
        self.client_secret = None

    def get_jwks(self, file_name: str):
        """
        Reads a JWKS file and loads the JSON web key set.
        file_name: The JWKS file containing your JSON Web Key Set.
        """
        with open(file_name, "r") as file:
            data = json.loads(file.read())
        self.settings["jwks"] = data
    
    def get_ssa(self, file_name: str):
        """
        Reads in a JSON file and loads the software statement
        https://www.rfc-editor.org/rfc/rfc7591.html#section-2
        """
        with open(file_name, "r") as file:
            data = json.loads(file.read())
        self.settings["ssa"] = data

    def get_client(self):
        """
        Sends a POST request to the server for dynamic client registration.
        The client will optionally use private_key_jwt for authentication if
        ScimClient.get_jwks() was called. Otherwise, client_secret_basic will
        be used.
        """
        r = requests.get(self.settings["openid"], verify=self.settings["sslcert"])
        if r.status_code != 200:
            print("Request returned", r.status_code)
        else:
            data = r.json()
            reg = data["registration_endpoint"]
            self.settings["token_endpoint"] = data["token_endpoint"]
            print("Enter a name for the new client: ", end="")
            client_name = input()
            payload = {
                "application_type": "native",
                "redirect_uris": [self.settings["callback_uri"]],
                "client_name": client_name,
                "grant_types": ["client_credentials"],
            }

            if "jwks" in self.settings and self.settings["jwks"] is not None:
                payload["jwks"] = self.settings["jwks"]
                payload["token_endpoint_auth_method"] = "private_key_jwt"
                
            if "ssa" in self.settings and self.settings["ssa"] is not None:
                ssa = self.settings["ssa"]
                # Set the appropriate kid here
                headers = {
                    "kid": "abcdef",
                    "alg": "RS256",
                    "typ": "JWT"
                }
                signed = jws.sign(ssa, settings["privKey"],headers=headers, algorithm='RS256')
                assert(jws.verify(signed, settings["pubKey"], algorithms=["RS256"]))
                payload["software_statement"] = signed

            print(json.dumps(payload, indent=4))

            r2 = requests.post(reg, json=payload, verify=self.settings["sslcert"])

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


if __name__ == "__main__":
    with open("settings.json", "r") as f:
        settings = json.loads(f.read())

    if (
        not settings["hostname"]
        or not settings["callback_uri"]
        or not settings["sslcert"]
    ):
        print("Misconfigured settings.json. Please refer to settings-demo.json.")
        sys.exit()

    testClient = GluuClientReg(settings)

    if "jwks_path" in settings:
        testClient.get_jwks(settings["jwks_path"])
    
    if "ssa_path" in settings:
        testClient.get_ssa(settings["ssa_path"])
        try:
            with open(settings["privkey_path"]) as f:
                settings["privKey"] = f.read()
            with open(settings["pubkey_path"]) as f:
                settings["pubKey"] = f.read()
        except Exception:
            print("Key pair not found")

    testClient.get_client()
