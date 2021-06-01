# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with
# the License. A copy of the License is located at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import boto3
import json


def get_secret_details(secret_name, unauth_credentials):
    secret_details = {}
    secret_details['region'] = unauth_credentials['region']
    secret_client = boto3.client(
        'secretsmanager',
        region_name=unauth_credentials['region'],
        aws_access_key_id=unauth_credentials['uAccessKeyId'],
        aws_secret_access_key=unauth_credentials['uSecretKey'],
        aws_session_token=unauth_credentials['uSessionToken'])
    secret_response = secret_client.get_secret_value(SecretId=secret_name)
    [(secret_details['username'], secret_details['password'])
     ] = json.loads(secret_response['SecretString']).items()
    secret_response = secret_client.describe_secret(SecretId=secret_name)
    tag_list = secret_response['Tags']
    for tag_dict_item in range(len(tag_list)):
        if 'IoTEndpoint' in tag_list[tag_dict_item].values():
            secret_details['host'] = tag_list[tag_dict_item]['Value']
        elif 'IoTPolicy' in tag_list[tag_dict_item].values():
            secret_details['policyname'] = tag_list[tag_dict_item]['Value']
        elif 'ClientId' in tag_list[tag_dict_item].values():
            secret_details['clientId'] = tag_list[tag_dict_item]['Value']
        elif 'UserPoolId' in tag_list[tag_dict_item].values():
            secret_details['userpool'] = tag_list[tag_dict_item]['Value']
    return secret_details
