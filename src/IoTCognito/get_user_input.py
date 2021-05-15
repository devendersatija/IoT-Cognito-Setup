def get_user_input(config):
    user_data={}
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
    user_data['region']=config['CognitoIdentityPoolID'].split(':')[0]
    user_data['topic'] = config['topic'] 
    user_data['secret_name'] = config['secretname']
    user_data['rolearn'] = config['unauthrolearn'] 
    return user_data