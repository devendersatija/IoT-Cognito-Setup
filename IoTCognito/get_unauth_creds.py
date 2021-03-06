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


def get_unauth_credentials(user_data):
    unauth_credentials = {}
    unauth_credentials['region'] = user_data['region']
    cognitoIdentityClient = boto3.client(
        'cognito-identity', region_name=user_data['region'])
    temporaryUnAuthIdentityId = cognitoIdentityClient.get_id(
        IdentityPoolId=user_data['cognitoIdentityPoolID'])
    identityUnAuthID = temporaryUnAuthIdentityId["IdentityId"]
    temporaryOpenIdToken = cognitoIdentityClient.get_open_id_token(
        IdentityId=identityUnAuthID)
    sts_client = boto3.client('sts', region_name=user_data['region'])
    sts_response = sts_client.assume_role_with_web_identity(
        RoleArn=user_data['rolearn'],
        RoleSessionName=identityUnAuthID.split(':')[0],
        WebIdentityToken=temporaryOpenIdToken['Token'])
    unauth_credentials['uAccessKeyId'] = sts_response["Credentials"]["AccessKeyId"]
    unauth_credentials['uSecretKey'] = sts_response["Credentials"]["SecretAccessKey"]
    unauth_credentials['uSessionToken'] = sts_response["Credentials"]["SessionToken"]
    return unauth_credentials
