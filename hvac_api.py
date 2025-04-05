import hvac
import os
import requests
import urllib3
import re
import json
import base64
import sys
import glob


class Client:
    def __init__(self, url_domain, namespace, role_id, secret_id):
        self.client = None
        self.__token = None
        self.url_domain = url_domain
        self.namespace = namespace
        self.role_id = role_id
        self.secret_id = secret_id

    def show_info(self):
        return f"\nUrl = '{self.url_domain}', namespace = {self.namespace}, " \
               f"\nrole_id = {self.role_id}, secret_id = {self.secret_id}"

    def get_token(self):
        urllib3.disable_warnings()
        headers = {"Content-Type": "application/json", "x-vault-namespace": self.namespace}
        data = {"role_id": self.role_id, "secret_id": self.secret_id}
        post_response = requests.post('https://' + self.url_domain + '/v1/auth/approle/login', headers=headers,
                                      json=data, verify=False)
        post_response_json = post_response.json()
        self.__token = (post_response_json['auth']['client_token'])

    def client_auth(self):
        self.client = hvac.Client(
            url='https://' + self.url_domain,
            token=self.__token,
            namespace=self.namespace,
            verify=False
        )
        if self.client.is_authenticated():
            print("Connection Success!")
        else:
            print("Connection Error!")


class Secret(Client):
    def __init__(self, url_domain, namespace, role_id, secret_id, mount, path, ):
        super().__init__(url_domain, namespace, role_id, secret_id)
        self.full_path = namespace + mount + path
        self.new_path = ''
        self.secret_data_lst = []
        self.secret_name_lst = []
        self.secret_dirs_lst = []
        self.keys_dict = {}

    def show_info(self):
        return f"\nUrl = '{self.url_domain}', namespace = {self.namespace}, " \
               f"\nrole_id = {self.role_id}, secret_id = {self.secret_id}, " \
               f"\npath = {self.full_path}"

    def get_secret_list(self):
        urllib3.disable_warnings()
        try:
            response_dict = self.client.list(self.full_path)
            # check if 'data' exists in the json response
            if 'data' in response_dict.keys():
                self.keys_dict = response_dict['data']
            else:
                sys.exit(f"Error: Data for '{self.full_path}' was not found in Vault")
            # check if the 'keys' key exists in the keys_dict dictionary
            if 'keys' in self.keys_dict.keys():
                # return the list of data keys available under the vault mount_path path
                return f"List of secrets '{self.keys_dict['keys']}"
            else:
                sys.exit(f"Error: No information keys were found under '{self.full_path}' in Vault")
        except Exception as e:
            print(f"Failed to read from or find the path '{self.full_path}' in Vault")
            sys.exit("Error: " + str(e))

    def read_secrets(self):
        for key in self.keys_dict['keys']:
            secret = self.client.read('{}/{}'.format(self.full_path, key))
            last_char = key[-1:]
            if secret is not None:
                self.secret_data_lst.append(secret['data'])
                self.secret_name_lst.append(key)
            elif last_char == '/':
                self.secret_dirs_lst.append(key[:-1])
            else:
                raise TypeError
        return self.secret_data_lst, self.secret_name_lst, self.secret_dirs_lst

    def save_secrets(self):  # write secrets to files one by one
        for k, element in enumerate(self.secret_data_lst, 0):
            with open(self.secret_name_lst[k] + '.json', 'w', encoding='utf-8') as f:
                f.write(json.dumps(element))

    def decode_secrets(self):
        # read, decode and save files to dif directory with file's name
        path = '.'
        for filename in glob.glob(os.path.join(path, '*.json')):
            with open(os.path.join(os.getcwd(), filename), 'r', encoding='utf-8') as json_file:
                json_data = json.load(json_file)  # read json
                for key, value in json_data.items():
                    if self.is_base64(key, value):  # if base64 then decode
                        decoded = base64.b64decode(value)
                        if not os.path.exists(filename.rstrip('.json')):  # create folder with file's name
                            os.makedirs(filename.rstrip('.json'))
                        with open(os.path.join(filename.rstrip('.json'), key), 'wb') as decoded_file:
                            decoded_file.write(decoded)
                    else:  # if note base64 skip
                        if not os.path.exists(filename.rstrip('.json')):  # create folder with file's name
                            os.makedirs(filename.rstrip('.json'))
                        with open(os.path.join(filename.rstrip('.json'), key), 'w', encoding="utf-8") as decoded_file:
                            decoded_file.write(value)

    @staticmethod
    def is_base64(key, value):
        string = re.search('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$', value)
        if string:
            print(key, "Encoded base64")
            return True
        else:
            print(key, "Non encoded base64")
            return False

    def get_directories(self):
        for el in self.secret_dirs_lst:
            self.full_path = self.full_path + '/' + el
            return f"Current path = '{self.full_path}'"



if __name__ == '__main__':
     
    #for example
    secret_ms = Secret(url_domain='t.secrets.ru', namespace='CI02000000_CI02011111',
                       mount='/A/TEST/KV/', path='my-path',
                       role_id='7c3ed09e-4d39-c7d6-7972-bbc6e9e85a2d', secret_id='56f1f246-5760-3381-f738-0facc3ff68a6')
    print(secret_ms.show_info())
   
