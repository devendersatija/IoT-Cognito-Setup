import IoTCognito

# Update config parameters
config ={}
config['rootCA'] = 'AmazonRootCA1.pem'
config['unauthrolearn'] = 'arn:aws:iam::090642296363:role/aod-test-IdentityPoolUnAuthRole'
config['secretname'] = 'us-east-1_9aDQUEokH_aod-test-app-user'
config['CognitoIdentityPoolID'] = 'us-east-1:b32f6663-e33e-48e8-8245-62cf461a2973'
config['topic'] = 'test'

# call user input script to manage user data 
user_data = IoTCognito.get_user_input(config)
#print(user_data)

# Fetch AWS credentials using un-authenticated cognito identity IAM Role credentials. 
# This role only has access to read one secret dynamically based on the source IP address
unauth_credentials = IoTCognito.get_unauth_credentials(user_data)
#print(unauth_credentials)

# Fetch the secret details from AWS secret managers
secret_details = IoTCognito.get_secret_details(user_data['secret_name'],unauth_credentials)
#print(secret_details)

# Using the secret generate temporary IAM credentials for authenticated cognito Identity IAM credentials.
auth_credentials = IoTCognito.get_auth_creds(secret_details, user_data['cognitoIdentityPoolID'])

# Attach the cognito identity to IOT access policy. 
IoTCognito.attach_iot_policy(auth_credentials)

# Publish data over MQTT/WebSocket connection to IoT Core. 
# Uses Amazon Root CA, and port 443 for secure data transfer. 
IoTCognito.publish_mqtt(user_data, secret_details, auth_credentials)