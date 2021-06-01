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

def get_user_input(config):
    user_data = {}
    # Accept user data
    # parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    # parser.add_argument("-r", "--rootCA", action="store", required=True, dest="rootCAPath", help="Root CA file path")
    # parser.add_argument("-u", "--unauthrolearn", action="store", required=True, dest="unauthrole", help="ARN for the unauthenticated role")
    # parser.add_argument("-s", "--secretname", action="store", required=True, dest="secret", help="Secret Name")
    # parser.add_argument("-c", "--CognitoIdentityPoolID", action="store", required=True, dest="cognitoIdentityPoolID", help="Your AWS Cognito Identity Pool ID")
    # parser.add_argument("-t", "--topic", action="store", dest="topic", default="test", help="Targeted topic")
    # args = parser.parse_args()

    user_data['rootCAPath'] = config['rootCA']
    user_data['cognitoIdentityPoolID'] = config['CognitoIdentityPoolID']
    user_data['region'] = config['CognitoIdentityPoolID'].split(':')[0]
    user_data['topic'] = config['topic']
    user_data['secret_name'] = config['secretname']
    user_data['rolearn'] = config['unauthrolearn']
    return user_data
