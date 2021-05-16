import boto3
import json

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