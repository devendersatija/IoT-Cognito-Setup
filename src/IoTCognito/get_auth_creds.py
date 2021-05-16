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

def get_auth_creds(secret_details, cipid):
    # Cognito auth
    auth_credentials={}
    auth_credentials['region']=secret_details['region']
    auth_credentials['policyname']=secret_details['policyname']
    cognitoIdentityClient = boto3.client('cognito-identity', region_name=secret_details['region'])
    cognitoClient = boto3.client('cognito-idp', region_name=secret_details['region'])
    response = cognitoClient.initiate_auth(
        ClientId=secret_details['clientId'],
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={'USERNAME': secret_details['username'],'PASSWORD': secret_details['password']})
    accesstoken=response['AuthenticationResult']['AccessToken']
    idtoken=response['AuthenticationResult']['IdToken']
    refreshtoken=response['AuthenticationResult']['RefreshToken']
    provider_name ='cognito-idp.'+secret_details['region']+'.amazonaws.com/'+secret_details['userpool']
    # Get the users unique identity ID
    temporaryIdentityId = cognitoIdentityClient.get_id(IdentityPoolId=cipid,Logins={provider_name:idtoken})
    identityID = temporaryIdentityId["IdentityId"]
    # Exchange idtoken for AWS Temporary credentials
    temporaryCredentials = cognitoIdentityClient.get_credentials_for_identity(IdentityId=identityID,Logins={provider_name:idtoken})
    auth_credentials['AccessKeyId'] = temporaryCredentials["Credentials"]["AccessKeyId"]
    auth_credentials['SecretKey'] = temporaryCredentials["Credentials"]["SecretKey"]
    auth_credentials['SessionToken'] = temporaryCredentials["Credentials"]["SessionToken"]
    auth_credentials['identityID'] = identityID
    return auth_credentials