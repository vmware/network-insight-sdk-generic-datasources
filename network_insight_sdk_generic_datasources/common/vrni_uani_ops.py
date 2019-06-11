import requests
import json
import pprint

login_url = 'https://{}/api/ni/auth/token'
list_uani_url = 'https://{}/api/ni/data-sources/uani'
upload_uani_url = 'https://{}/api/ni/data-sources/uani/{}/data'
ni_token = 'NetworkInsight {}'
login_request_body = dict(username='', password='', domain=dict(domain_type='LOCAL'))


def login(host, username, password):
    url = login_url.format(host)
    login_request_body['username'] = username
    login_request_body['password'] = password
    response = requests.post(url, json.dumps(login_request_body), verify=False,
                             headers={"content-type": "application/json"})
    return response.json().get('token')


def list_uani_data_source(host, token):
    list_url = list_uani_url.format(host)
    response = requests.get(list_url, verify=False, headers={"content-type": "application/json",
                                                             "Authorization": ni_token.format(token)})
    model_keys = []
    for entry in response.json()['results']:
        model_keys.append(entry['entity_id'])
    return model_keys


def get_uani_data_source(host, token):
    model_keys = list_uani_data_source(host, token)
    uani_object = []
    for mk in model_keys:
        get_url = (list_uani_url + '/{}').format(host, mk.replace(':', '%3A', 2))
        response = requests.get(get_url, verify=False,
                                headers={"content-type": "application/json", "Authorization": ni_token.format(token)})
        uani_object.append(response.json())
    return uani_object


def update_uani_file(host, token, model_key):
    upload_file_url = upload_uani_url.format(host, model_key.replace(':', '%3A', 2))
    file_location = '/tmp/cisco-device.zip'
    filename = file_location.split('/')[-1]
    data = open(file_location, 'rb')
    response = requests.put(upload_file_url,
                            files={'file': (filename, data, 'application/octet-stream')},
                            verify=False,
                            headers={"Authorization": ni_token.format(token)})
    pprint.pprint(response.status_code)


def main():
    host = '10.153.188.228'
    token = login(host, 'admin@local', 'admin')
    uani_json = get_uani_data_source(host, token)
    # mk = uani_json[0]['entity_id'].replace(':', '%3A', 2)
    mk = uani_json[0]['entity_id']
    update_uani_file(host, token, mk)


if __name__ == '__main__':
    main()

