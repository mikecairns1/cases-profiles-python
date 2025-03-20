from flask import render_template, jsonify
import boto3
from botocore.exceptions import ClientError

@app.route('/qic')
def qic_page():
    try:
        # Get AWS credentials from your session or configuration
        session = boto3.Session(
            aws_access_key_id=session.get('access_key'),
            aws_secret_access_key=session.get('secret_key'),
            aws_session_token=session.get('session_token'),
            region_name=session.get('region')
        )
        
        qconnect_client = session.client('qconnect')
        
        # List all knowledgebases
        knowledgebases = []
        paginator = qconnect_client.get_paginator('list_knowledge_bases')
        
        for page in paginator.paginate():
            knowledgebases.extend(page.get('knowledgeBaseSummaries', []))
        
        return render_template('qic.html', knowledgebases=knowledgebases)
        
    except ClientError as e:
        return render_template('qic.html', error=str(e), knowledgebases=[]) 