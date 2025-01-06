# © 2024 by Cloudera, Inc. All rights reserved.
# Scripts and sample code are licensed under the Apache License,
# Version 2.0

import click
import requests
from requests.auth import HTTPBasicAuth
import json
@click.command()
@click.option('--username', prompt='Your username', help='The username for Knox authentication.')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=False, help='The password for Knox authentication.')
@click.option('--knox-url', prompt='Knox topology endpoint URL', default='https://localhost:8443/gateway/cdp-share-management/', help='The Knox API topology endpoint url.')
@click.option('--contact', prompt='Knox Share Contact (email)', default='n/a', help='The contact email for the share.' )
@click.option('--comment', prompt='Comment for the Share', default='CLIENT_ID, CLIENT_SECRET for external sharing', help='Comment to describe the intent of this share.')
@click.option('--role', prompt='Ranger Role name', default='none', help='The Ranger Role to add the Group to.' )
def create_knox_share(username, password, knox_url, contact, comment, role):
    database = 'none'
    table = 'none'
    qp = '?'
    if (knox_url.find('?') != -1):
        qp = '&'
    response = requests.get(knox_url + 'knoxtoken/api/v1/token' + qp
        + 'doAs=external.user&comment=' + comment
        + '&md_contact=' + contact
        + '&md_role=' + role
        + '&md_type=CLIENT_ID',
         auth=HTTPBasicAuth(username, password), verify=False)
    print(response)
    if response.status_code == 200:
        token_data = response.json()
        print(f"CLIENT_ID: {token_data.get('token_id')}")
        print(f"CLIENT_SECRET: {token_data.get('passcode')}")
        print(f"CONTACT: {contact}")
        print("...............................................................")
        print(f"*Creating Ranger Group for {token_data.get('token_id')}")
        group_id = create_ranger_group(username, password, knox_url, token_data.get('token_id'))
        group_id_str = str(group_id)
        if (database != 'none'):
            create_ranger_policy(username, password, knox_url, group_id_str, database, table)
        if (role != 'none'):
            print("...............................................................")
            role_id = create_ranger_role(username, password, knox_url, group_id_str, role)
            role_id_str = str(role_id)
            print("...............................................................")
            add_group_to_role(username, password, knox_url, group_id_str, token_data.get('token_id'), role_id_str, role)
    else:
        print('Failed to retrieve the token. Please check your credentials and Knox URL.')
        print(f"Error: {response.text}")
def create_ranger_group(username, password, knox_url, client_id):
    url = knox_url + "ranger/service/xusers/groups/"
    print(f"URL to Ranger: {url}")
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "name": client_id,
        "description": "group representing a share for a CLIENT_ID"
    }
    print(data)
    response = requests.post(url, headers=headers, json=data, auth=HTTPBasicAuth(username, password), verify=False)  # Set verify to False if using self-signed certificates
    print(response.text)
    if response.status_code == 200:
        print("Group added successfully.")
        return response.json().get("id")
    else:
        print("Failed to add group. Status code:", response.status_code)
        print(response)
def create_ranger_policy(username, password, knox_url, client_id, database, table):
    # Define the necessary information for the API call
    if (table == 'none'):
        table = '*'
    url = knox_url + "ranger/service/public/v2/policy"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    data = {
        "policyType": 0,
        "name": "Hive Table Policy",
        "description": "Policy for SELECT access to a specific group",
        "isEnabled": True,
        "resources": {
            "database": {
                "values": [database]
            },
            "table": {
                "values": [table]
            }
        },
        "policyItems": [
            {
                "accesses": [
                    {
                        "type": "select"
                    }
                ],
                "users": [],
                "groups": [client_id],
                "conditions": []
            }
        ]
    }
    # Make the API call to add the policy
    response = requests.post(url, headers=headers, json=data, auth=HTTPBasicAuth(username, password), verify=False)
    print(response)
    # Check the response status
    if response.status_code == 200:
        print("Hive table policy added successfully.")
    else:
        print("Failed to add Hive table policy. Status code:", response.status_code)
def create_ranger_role(username, password, knox_url, client_id, role):
    # determine whether it is an existing role before adding one
    url = knox_url + "ranger/service/roles/roles/name/" + role +"?execUser=" + username
    print(url)
    # Make the API call to add the new Ranger role
    response = requests.get(url, auth=HTTPBasicAuth(username, password), verify=False)
    print(response.text)
    # Check the response status
    print(response)
    if response.status_code == 200:
        print("New Ranger role added successfully.")
        return response.json().get("id")
    else:
        url = knox_url + "ranger/service/roles/roles"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        data = {
            "name": role,
            "description": "Role created for datasharing",
            "isAdminRole": False
        }
        #print(data)
        # Make the API call to add the new Ranger role
        response = requests.post(url, headers=headers, json=data, auth=HTTPBasicAuth(username, password), verify=False)
        # Check the response status
        print(response)
        if response.status_code == 200:
            print("New Ranger role updated successfully.")
            return response.json().get("id")
        else:
            print("Failed to add new Ranger role. Status code:", response.status_code)
def add_group_to_role(username, password, knox_url, client_id, group_name, role_id, role_name):
    # determine whether it is an existing role before adding the group
    url = knox_url + "ranger/service/roles/roles/name/" + role_name +"?execUser=" + username
    print(url)
    # Make the API call to add the new Ranger role
    response = requests.get(url, auth=HTTPBasicAuth(username, password), verify=False)
    print(response.text)
    groups = response.json().get("groups")
    if (groups is None):
        groups = []
    new_group = {"id": client_id, "name": group_name, "isAdminRole": False}
    groups.append(new_group)
    url = knox_url + "ranger/service/roles/roles/" + role_id
    print(url)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    data = {
        "name": role_name,
        "users": [],
        "groups": groups
    }
    # Make the API call to add the group to the role
    response = requests.put(url, headers=headers, json=data, auth=HTTPBasicAuth(username, password), verify=False)
    print("Response Text: " + response.text)
    # Check the response status
    if response.status_code == 200:
        print("Apache Ranger group added to Ranger role successfully.")
    else:
        print("Failed to add Apache Ranger group to Ranger role. Status code:", response.status_code)
if __name__ == '__main__':
    create_knox_share()
