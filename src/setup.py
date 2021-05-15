import IoTCognito

config ={}
config['rootCA'] = 'AmazonRootCA1.pem'
config['unauthrolearn'] = 'arn:aws:iam::090642296363:role/aod-test-IdentityPoolUnAuthRole'
config['secretname'] = 'us-east-1_XryoTVf4g_aod-test-app-user'
config['CognitoIdentityPoolID'] = 'us-east-1:f4d030fc-a484-4dd6-8785-32690c180058'
config['topic'] = 'test'

user_data = IoTCognito.get_user_input(config)
print(user_data)

unauth_credentials = IoTCognito.get_unauth_credentials(user_data)
print(unauth_credentials)

secret_details = IoTCognito.get_secret_details(user_data['secret_name'],unauth_credentials)
print(secret_details)

auth_credentials = IoTCognito.get_auth_creds(secret_details, user_data['cognitoIdentityPoolID'])
print(auth_credentials)

#IoTCognito.publish_mqtt(user_data, secret_details, auth_credentials)