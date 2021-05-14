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

# Accept user data
parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-u', '--username', required=True, help='Specify username',default=getpass.getuser())
parser.add_argument('-p', '--password', required=True, type=Password, help='Specify password',default=Password.DEFAULT)
parser.add_argument("-r", "--rootCA", action="store", required=True, dest="rootCAPath", help="Root CA file path")
parser.add_argument("-s", "--secretarn", action="store", required=True, dest="secret", help="ARN for Secret")
parser.add_argument("-C", "--CognitoIdentityPoolID", action="store", required=True, dest="cognitoIdentityPoolID", help="Your AWS Cognito Identity Pool ID")
parser.add_argument("-id", "--clientId", action="store", dest="clientId", default="basicPubSub_CognitoSTS",help="Targeted client id")
parser.add_argument("-t", "--topic", action="store", dest="topic", default="test", help="Targeted topic")
args = parser.parse_args()

username=args.username
password=str(args.password)
rootCAPath = args.rootCAPath
clientId = args.clientId
cognitoIdentityPoolID = args.cognitoIdentityPoolID
topic = args.topic
secret_arn = args.secret
secret_arn = secret_arn.split(':')
region=secret_arn[3]
secret_name = secret_arn[6].rsplit('-', 1)[0]
userpool = secret_name.rsplit('_', 1)[0]
username = secret_name.rsplit('_', 1)[1]

# Configure logging
logger = logging.getLogger("AWSIoTPythonSDK.core")
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
streamHandler.setFormatter(formatter)
logger.addHandler(streamHandler)

# Cognito auth
cognitoIdentityClient = boto3.client('cognito-identity', region_name=region)
cognitoClient = boto3.client('cognito-idp', region_name=region)
response = cognitoClient.initiate_auth(
    ClientId=clientId,
    AuthFlow='USER_PASSWORD_AUTH',
    AuthParameters={'USERNAME': username,'PASSWORD': password})

accesstoken=response['AuthenticationResult']['AccessToken']
idtoken=response['AuthenticationResult']['IdToken']
refreshtoken=response['AuthenticationResult']['RefreshToken']
provider_name ='cognito-idp.'+region+'.amazonaws.com/'+userpool

# Get the users unique identity ID
temporaryIdentityId = cognitoIdentityClient.get_id(IdentityPoolId=cognitoIdentityPoolID,Logins={provider_name:idtoken})
identityID = temporaryIdentityId["IdentityId"]

# Exchange idtoken for AWS Temporary credentials
temporaryCredentials = cognitoIdentityClient.get_credentials_for_identity(IdentityId=identityID,Logins={provider_name:idtoken})
AccessKeyId = temporaryCredentials["Credentials"]["AccessKeyId"]
SecretKey = temporaryCredentials["Credentials"]["SecretKey"]
SessionToken = temporaryCredentials["Credentials"]["SessionToken"]

# Get secret info from aws sercrets manager
secret_client=boto3.client('secretsmanager', region_name=region,aws_access_key_id=AccessKeyId,aws_secret_access_key=SecretKey,aws_session_token=SessionToken)
secret_response = secret_client.describe_secret(SecretId=secret_name)
tag_list=secret_response['Tags']
for tag_dict_item in range(len(tag_list)):
    if 'IoTEndpoint' in tag_list[tag_dict_item].values():
        host = tag_list[tag_dict_item]['Value']
    elif 'IoTPolicy' in tag_list[tag_dict_item].values():
        policyname = tag_list[tag_dict_item]['Value']

# Attach IoT policy to identity
iot_client = boto3.client('iot', region_name=region, aws_access_key_id=AccessKeyId,
    aws_secret_access_key=SecretKey,
    aws_session_token=SessionToken)
iot_response = iot_client.attach_policy(
    policyName=policyname,
    target=identityID
)

# Init AWSIoTMQTTClient.
# MQTT client can only connect if MQTT client is same as unique identity ID. 
# Client can only write to CognitoIdentityPoolId/IdentityID/*
mqtttopic = cognitoIdentityPoolID + "/" + identityID + "/" + topic
# only allow client with identity id to conenct
myAWSIoTMQTTClient = AWSIoTMQTTClient(identityID, useWebsocket=True)

# AWSIoTMQTTClient configuration
myAWSIoTMQTTClient.configureEndpoint(host, 443)
myAWSIoTMQTTClient.configureCredentials(rootCAPath)
myAWSIoTMQTTClient.configureIAMCredentials(AccessKeyId, SecretKey, SessionToken)
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