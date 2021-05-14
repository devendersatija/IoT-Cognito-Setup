import boto3
from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient
import logging
import time
import json

# Custom MQTT message callback
def customCallback(client, userdata, message):
    print("Received a new message: ")
    print(message.payload)
    print("from topic: ")
    print(message.mqtttopic)
    print("--------------\n\n")

# Configure logging
logger = logging.getLogger("AWSIoTPythonSDK.core")
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
streamHandler.setFormatter(formatter)
logger.addHandler(streamHandler)

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