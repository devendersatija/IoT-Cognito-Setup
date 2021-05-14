import argparse
import getpass

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
    parser.add_argument("-c", "--CognitoIdentityPoolID", action="store", required=True, dest="cognitoIdentityPoolID", help="Your AWS Cognito Identity Pool ID")
    parser.add_argument("-t", "--topic", action="store", dest="topic", default="test", help="Targeted topic")
    args = parser.parse_args()
    user_data['rootCAPath'] = args.rootCAPath
    user_data['cognitoIdentityPoolID'] = args.cognitoIdentityPoolID
    user_data['region']=user_data['cognitoIdentityPoolID'].split(':')[0]
    user_data['topic'] = args.topic
    user_data['secret_name'] = args.secret
    user_data['rolearn'] = args.unauthrole
    return user_data