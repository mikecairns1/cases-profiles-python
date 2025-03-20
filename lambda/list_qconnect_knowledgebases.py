import os
import json
import boto3
from botocore.exceptions import ClientError

# AWS clients setup
AWS_REGION = os.environ.get('AWS_REGION', 'us-west-2')
qconnect_client = boto3.client('qconnect')

def lambda_handler(event, context):
    print("Event Received: ", json.dumps(event))
    
    response_data = {
        "statusCode": "",
        "body": "",
        "knowledgeBases": []
    }
    
    try:
        # List all knowledgebases
        paginator = qconnect_client.get_paginator('list_knowledge_bases')
        
        # Collect all knowledgebases across pages
        for page in paginator.paginate():
            response_data["knowledgeBases"].extend(page.get("knowledgeBaseSummaries", []))
            
        response_data.update({
            "statusCode": 200,
            "body": "Successfully retrieved knowledgebases"
        })
        
    except ClientError as e:
        print(f"ClientError - ListKnowledgeBases - {e}")
        response_data.update({
            "statusCode": 500,
            "body": f"Error listing knowledgebases: {str(e)}"
        })
    
    print(f"Response Data: {json.dumps(response_data, default=str)}")
    return response_data 