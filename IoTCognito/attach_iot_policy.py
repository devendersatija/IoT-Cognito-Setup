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


def attach_iot_policy(auth_credentials):
    # Attach IoT policy to identity
    iot_client = boto3.client(
        'iot',
        region_name=auth_credentials['region'],
        aws_access_key_id=auth_credentials['AccessKeyId'],
        aws_secret_access_key=auth_credentials['SecretKey'],
        aws_session_token=auth_credentials['SessionToken'])
    iot_response = iot_client.attach_policy(
        policyName=auth_credentials['policyname'],
        target=auth_credentials['identityID']
    )
