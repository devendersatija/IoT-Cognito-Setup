import IoTCognito
import argparse

# Read in command-line parameters
config = {}
config['rootCA'] = 'AmazonRootCA1.pem'
#config['unauthrolearn'] = 'arn:aws:iam::090642296363:role/demo-IdentityPoolUnAuthRole'
#config['secretname'] = 'us-east-1_DUfiPo1bd_demo-app-user'
#config['CognitoIdentityPoolID'] = 'us-east-1:8f5d65fb-217f-41da-8aee-7595a24e9af4'
#config['topic'] = 'test'
parser = argparse.ArgumentParser(description='User data input for the pipeline')
parser.add_argument("-u", "--unauthrolearn", action="store", required=True, dest="unauthrole", help="ARN for Cognito Identity unauthorized role")
parser.add_argument("-s", "--secretname", action="store", required=True, dest="secret", help="Secret Name")
parser.add_argument("-c", "--cognitoidentitypoolid", action="store", required=True, dest="cognitoidentitypoolid", help="Cognito Identity Pool ID")
parser.add_argument("-t", "--topic", action="store", dest="topic", default="test", help="Targeted topic")
args = parser.parse_args()
config['unauthrolearn'] = args.unauthrole
config['secretname'] = args.secret
config['CognitoIdentityPoolID'] = args.cognitoidentitypoolid
config['topic'] = args.topic

# call user input script to manage user data
user_data = IoTCognito.get_user_input(config)
# print(user_data)

# Fetch AWS credentials using un-authenticated cognito identity IAM Role credentials.
# This role only has access to read one secret dynamically based on the
# source IP address
unauth_credentials = IoTCognito.get_unauth_credentials(user_data)
# print(unauth_credentials)

# Fetch the secret details from AWS secret managers
secret_details = IoTCognito.get_secret_details(
    user_data['secret_name'], unauth_credentials)
# print(secret_details)

# Using the secret generate temporary IAM credentials for authenticated
# cognito Identity IAM credentials.
auth_credentials = IoTCognito.get_auth_creds(
    secret_details, user_data['cognitoIdentityPoolID'])

# Attach the cognito identity to IOT access policy.
IoTCognito.attach_iot_policy(auth_credentials)

# Publish data over MQTT/WebSocket connection to IoT Core.
# Uses Amazon Root CA, and port 443 for secure data transfer.
IoTCognito.publish_mqtt(user_data, secret_details, auth_credentials)
