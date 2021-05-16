# IoT-Cognito-Setup
how to use cognito identities with unregistered IoT devices/and python sdk. 

## Design Principles
1. __Principle1__ - dsfkdfsdfsdf
sdfsdkfjsdlfsd
dsf
sdf
sdf
2. __Principle2__ - 



## How to run cloudformation
Cloudformation takes three parameters. 
Parameter Name | Description
------------ | -------------
Prefix | Prefix for all resources to be created
Email | email address related to the owner, and is used for user sign up in cognito
IpAddress | A valid IP address for the device

```console
IPADDRESS='107.141.235.104'
PREFIX="aod-test"
EMAIL="satijads@amazon.com"
STACK_NAME=$PREFIX-cognito-iot-setup
OWNER="satijads"
PROJECT=$PREFIX-mvp

#aws cloudformation delete-stack --stack-name $STACK_NAME 

aws cloudformation deploy --template cognito.yml --stack-name $STACK_NAME --parameter-overrides Prefix=$PREFIX Email=$EMAIL IpAddress=$IPADDRESS --tags Project=$PROJECT Owner=$OWNER --capabilities CAPABILITY_NAMED_IAM


```

## List of Resources
Logical Name | Description
------------ | -------------
CognitoUserPool | Cognito User Pool
CognitoUserPoolClient | One client for all users in user pool
CognitoUserLambdaFunction | Lambda function to generate a random credential, create the user and save the info in the secret manager.
CognitoUserPoolUserCreation | Custom cloudformation resource to trigger the lambda above. 
CognitoIdentityPool | Cognito Identity Pool
CognitoIdentityPoolRoleAttachment | Attaches the authenticated and un-authenticated role to the identity pool
IAMAuthenticatedRole | Authenticated Role for cognito identities
IAMUnAuthenticatedRole | Un-Authenticated role for cognito Identities
IAMLambdaExecutionRole | Lambda execution role for pre-sign up lambda 'LambdaFunction'
IAMLambdaExecutionRole2 | Lambda execution role for user creation lambda 'CognitoUserLambdaFunction'
LambdaFunction | Lambda function as a pre-sign up trigger for cognito user pool to automatically confirm the user in amazon domain
LambdaPermission | Allowing cognito to invoke pre-sign up lambda
SecretResourcePolicy | Resource policy for the secret created, deny access to all IPs except the resource IP