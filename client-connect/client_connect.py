import boto3
from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient
import logging
import time
import argparse
import getpass
import json

# Custom MQTT message callback
def customCallback(client, userdata, message):
    print("Received a new message: ")
    print(message.payload)
    print("from topic: ")
    print(message.mqtttopic)
    print("--------------\n\n")

class Password:
    DEFAULT = 'Prompt if not specified'
    def __init__(self, value):
        if value == self.DEFAULT:
            value = getpass.getpass('Cognito User Account Password: ')
        self.value = value
    def __str__(self):
        return self.value


def user_input():
    user_data={}
    # Accept user data
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-r", "--rootCA", action="store", required=True, dest="rootCAPath", help="Root CA file path")
    parser.add_argument("-u", "--unauthrolearn", action="store", required=True, dest="unauthrole", help="ARN for the unauthenticated role")
    parser.add_argument("-s", "--secretname", action="store", required=True, dest="secret", help="Secret Name")
    parser.add_argument("-C", "--CognitoIdentityPoolID", action="store", required=True, dest="cognitoIdentityPoolID", help="Your AWS Cognito Identity Pool ID")
    parser.add_argument("-t", "--topic", action="store", dest="topic", default="test", help="Targeted topic")
    args = parser.parse_args()
    user_data['rootCAPath'] = args.rootCAPath
    user_data['cognitoIdentityPoolID'] = args.cognitoIdentityPoolID
    user_data['region']=user_data['cognitoIdentityPoolID'].split(':')[0]
    user_data['topic'] = args.topic
    user_data['secret_name'] = args.secret
    return user_data

# Configure logging
logger = logging.getLogger("AWSIoTPythonSDK.core")
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
streamHandler.setFormatter(formatter)
logger.addHandler(streamHandler)

def get_unauth_credentials(cipid, region, rolearn):
    unauth_credentials={}
    unauth_credentials['region']=region
    cognitoIdentityClient = boto3.client('cognito-identity', region_name=region)
    temporaryUnAuthIdentityId = cognitoIdentityClient.get_id(IdentityPoolId=cipid)
    identityUnAuthID = temporaryUnAuthIdentityId["IdentityId"]
    temporaryOpenIdToken = cognitoIdentityClient.get_open_id_token(IdentityId=identityUnAuthID)
    sts_client = boto3.client('sts', region_name=region)
    sts_response = sts_client.assume_role_with_web_identity(
        RoleArn=rolearn,
        RoleSessionName=identityUnAuthID,
        WebIdentityToken=temporaryOpenIdToken['Token'])
    unauth_credentials['uAccessKeyId'] = sts_response["Credentials"]["AccessKeyId"]
    unauth_credentials['uSecretKey'] = sts_response["Credentials"]["SecretAccessKey"]
    unauth_credentials['uSessionToken'] = sts_response["Credentials"]["SessionToken"]
    return unauth_credentials

def get_secret_details(secret_name,unauth_credentials):
    secret_details={}
    secret_details['region']=unauth_credentials['region']
    secret_client=boto3.client('secretsmanager', region_name=unauth_credentials['region'],
        aws_access_key_id=unauth_credentials['uAccessKeyId'],aws_secret_access_key=unauth_credentials['uSecretKey'],
        aws_session_token=unauth_credentials['uSessionToken'])
    secret_response=secret_client.get_secret_value(SecretId=secret_name)
    [(secret_details['username'],secret_details['password'])]=json.loads(secret_response['SecretString']).items()
    secret_response = secret_client.describe_secret(SecretId=secret_name)
    tag_list=secret_response['Tags']
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

def get_auth_credentials(secret_details, cipid):
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

def attach_iot_policy(auth_credentials):
    # Attach IoT policy to identity
    iot_client = boto3.client('iot', region_name=auth_credentials['region'], aws_access_key_id=auth_credentials['AccessKeyId'],
        aws_secret_access_key=auth_credentials['SecretKey'],
        aws_session_token=auth_credentials['SessionToken'])
    iot_response = iot_client.attach_policy(
        policyName=auth_credentials['policyname'],
        target=auth_credentials['identityID']
    )

def publish_mqtt(cipid,user_data,secret_details,auth_credentials):
    # Init AWSIoTMQTTClient.
    # MQTT client can only connect if MQTT client is same as unique identity ID. 
    # Client can only write to CognitoIdentityPoolId/IdentityID/*
    cognitoIdentityPoolID = cipid
    mqtttopic = cognitoIdentityPoolID + "/" + auth_credentials['identityID'] + "/" + user_data['topic']
    # only allow client with identity id to conenct
    myAWSIoTMQTTClient = AWSIoTMQTTClient(auth_credentials['identityID'], useWebsocket=True)
    # AWSIoTMQTTClient configuration
    myAWSIoTMQTTClient.configureEndpoint(secret_details['host'], 443)
    myAWSIoTMQTTClient.configureCredentials(user_data['rootCAPath'])
    myAWSIoTMQTTClient.configureIAMCredentials(auth_credentials['AccessKeyId'] , auth_credentials['SecretKey'], auth_credentials['SessionToken'])
    myAWSIoTMQTTClient.configureAutoReconnectBackoffTime(1, 32, 20)
    myAWSIoTMQTTClient.configureOfflinePublishQueueing(-1)  # Infinite offline Publish queueing
    myAWSIoTMQTTClient.configureDrainingFrequency(2)  # Draining: 2 Hz
    myAWSIoTMQTTClient.configureConnectDisconnectTimeout(10)  # 10 sec
    myAWSIoTMQTTClient.configureMQTTOperationTimeout(5)  # 5 sec
    # Connect and subscribe to AWS IoT
    myAWSIoTMQTTClient.connect()
    myAWSIoTMQTTClient.subscribe(mqtttopic, 1, customCallback)
    time.sleep(2)
    # Publish to the same topic in a loop forever
    loopCount = 0
    while True:
        message = {'Message from authenticated cognito identity':loopCount}
        myAWSIoTMQTTClient.publish(mqtttopic, json.dumps(message), 1)
        loopCount += 1
        time.sleep(1)