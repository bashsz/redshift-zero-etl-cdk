import json
import sys
from pip._internal import main

# TODO - Remove once Lambda runtimes https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html run the below boto version
main(['install', '-I', '-q', 'boto3==1.34.49', '--target', '/tmp/', '--no-cache-dir', '--disable-pip-version-check'])
sys.path.insert(0,'/tmp/')


import urllib.request

import boto3
# Initialize AWS clients
s3_client = boto3.client('s3')
redshift = boto3.client('redshift')
sts = boto3.client('sts')
rds = boto3.client('rds')


def handler(event, context):
    try:
        print("Received event: " + str(event))

        # Example logic to handle different CloudFormation events
        request_type = event['RequestType']
        source_arn_value = event['ResourceProperties']['source_arn_value']
        target_arn_value = event['ResourceProperties']['target_arn_value']

        if request_type == 'Create':
            # Your create logic here
            print("In create")
            # Perform Redshift Cluster and Integration creation
            create_redshift_authorization(source_arn_value, target_arn_value)
            create_integration(source_arn_value, target_arn_value)
            send_response(event, context, 'SUCCESS', "success")
        elif request_type == 'Update':
            # Your update logic here
            print("In update")
            # Perform Redshift Cluster and Integration creation
            create_redshift_authorization(source_arn_value, target_arn_value)
            create_integration(source_arn_value, target_arn_value)
            send_response(event, context, 'SUCCESS', "success")
            pass
        elif request_type == 'Delete':
            # Your delete logic here
            print("In delete")
            delete_integration(source_arn_value)
            send_response(event, context, 'SUCCESS', "success")
            pass

    except Exception as e:
        print(str(e))
        send_response(event, context, 'FAILED', {})


def send_response(event, context, response_status, response_data):
    print("In send_response")
    response_url = event['ResponseURL']
    response_body = {
        'Status': response_status,
        'Reason': 'See the details in CloudWatch Log Stream: ' + context.log_stream_name,
        'PhysicalResourceId': context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': response_data
    }

    json_response_body = json.dumps(response_body)

    headers = {
        'content-type': '',
        'content-length': str(len(json_response_body))
    }

    try:
        req = urllib.request.Request(response_url, data=json_response_body.encode(), headers=headers, method='PUT')
        with urllib.request.urlopen(req) as response:
            print("Response status:", response.reason)
            print("Response body:", response.read().decode('utf-8'))
    except Exception as e:
        print("Failed to send response: ", str(e))


def create_redshift_authorization(source_arn, target_arn):
    # Retrieve the current user's account ID
    response = sts.get_caller_identity()
    account_id = response['Account']

    # Create a resource policy specifying cluster ARN and account ID
    response = redshift.put_resource_policy(
        ResourceArn=target_arn,
        Policy='''
        {
            \"Version\":\"2012-10-17\",
            \"Statement\":[
                {\"Effect\":\"Allow\",
                \"Principal\":{
                    \"Service\":\"redshift.amazonaws.com\"
                },
                \"Action\":[\"redshift:AuthorizeInboundIntegration\"],
                \"Condition\":{
                    \"StringEquals\":{
                        \"aws:SourceArn\":\"%s\"}
                    }
                },
                {\"Effect\":\"Allow\",
                \"Principal\":{
                    \"AWS\":\"arn:aws:iam::%s:root\"},
                \"Action\":\"redshift:CreateInboundIntegration\"}
            ]
        }
        ''' % (source_arn, account_id)
    )
    print("Added redshift auth "+ str(response))
    return(response)

def create_integration(source_arn, target_arn):
    """Creates a zero-ETL integration using the source and target clusters"""

    response = rds.create_integration(
        SourceArn=source_arn,
        TargetArn=target_arn,
        IntegrationName='rds-redshift-integration'
    )
    print('Creating integration: ' + response['IntegrationName'])


def delete_integration(source_arn):
    """Deletes a zero-ETL integration using the source and target clusters"""
    # TODO - The logic looks at only first integration and deletes it. 
    print("In delete_integration")
    response = rds.describe_integrations(
        Filters=[
            {
                'Name': 'source-arn',
                'Values': [
                    source_arn,
                ]
            }
        ],
    )
    print(response)

    delete_response = rds.delete_integration(
        IntegrationIdentifier=response['Integrations'][0]['IntegrationArn']
    )
    print('Deleting integration: ' + delete_response)
