import json
import os
import base64
import hashlib
import hmac
import uuid
import boto3

dynamodb = boto3.client('dynamodb')
TABLE = os.environ['TABLE_QUIZ']
SECRET = os.environ['JWT_SECRET']

def decode_jwt(token, secret):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        msg = f"{header}.{payload}".encode()
        signature = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        if expected != sig:
            return None
        payload_json = base64.urlsafe_b64decode(payload + '==')
        return json.loads(payload_json.decode())
    except:
        return None

def lambda_handler(event, context):
    headers = event.get('headers', {})
    token = headers.get('Authorization') or headers.get('authorization')
    if not token or not token.startswith('Bearer '):
        return { 'statusCode': 401, 'body': json.dumps({ 'message': 'Missing token' }) }

    user = decode_jwt(token.replace('Bearer ', ''), SECRET)
    if not user or user.get('role') != 'creator':
        return { 'statusCode': 403, 'body': json.dumps({ 'message': 'Access denied' }) }

    body = json.loads(event['body'])
    activity_id = body.get('activityId')
    questions = body.get('questions')

    if not activity_id or not questions:
        return { 'statusCode': 400, 'body': json.dumps({ 'message': 'Missing activityId or questions' }) }

    try:
        for q in questions:
            question_id = str(uuid.uuid4())
            normalized_skill = q['relatedSkill'].strip().title()

            dynamodb.put_item(
                TableName=TABLE,
                Item={
                    'activityId': {'S': activity_id},
                    'questionId': {'S': question_id},
                    'question': {'S': q['question']},
                    'options': {'L': [{'S': opt} for opt in q['options']]},
                    'correctAnswer': {'S': q['correctAnswer']},
                    'relatedSkill': {'S': normalized_skill}
                }
            )
        return {
            'statusCode': 200,
            'headers': { 'Access-Control-Allow-Origin': '*' },
            'body': json.dumps({ 'message': 'Questions added' })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({ 'message': 'Failed to add questions', 'error': str(e) })
        }
