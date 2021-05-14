import boto3

def attach_iot_policy(auth_credentials):
    # Attach IoT policy to identity
    iot_client = boto3.client('iot', region_name=auth_credentials['region'], aws_access_key_id=auth_credentials['AccessKeyId'],
        aws_secret_access_key=auth_credentials['SecretKey'],
        aws_session_token=auth_credentials['SessionToken'])
    iot_response = iot_client.attach_policy(
        policyName=auth_credentials['policyname'],
        target=auth_credentials['identityID']
    )
