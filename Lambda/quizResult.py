import json
import os
import boto3
import base64
import hashlib
import hmac
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ['TABLE_SUBMISSIONS']
JWT_SECRET = os.environ['JWT_SECRET']

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Methods": "GET,OPTIONS"
}

def decode_jwt(token, secret):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature_b64 = parts
        message = f"{header_b64}.{payload_b64}".encode()
        signature_check = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        expected_sig = base64.urlsafe_b64encode(signature_check).rstrip(b'=').decode()

        if expected_sig != signature_b64:
            return None

        payload_json = base64.urlsafe_b64decode(payload_b64 + '==')
        return json.loads(payload_json.decode())
    except:
        return None

def convert(obj):
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    if isinstance(obj, list):
        return [convert(i) for i in obj]
    if isinstance(obj, dict):
        return {k: convert(v) for k, v in obj.items()}
    return obj

def lambda_handler(event, context):
    if event.get('httpMethod') == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': CORS_HEADERS,
            'body': json.dumps({ 'message': 'CORS preflight' })
        }

    headers = event.get('headers', {})
    token = headers.get('Authorization') or headers.get('authorization')

    if not token or not token.startswith('Bearer '):
        return {
            'statusCode': 401,
            'headers': CORS_HEADERS,
            'body': json.dumps({ 'message': 'Missing or invalid token' })
        }

    user = decode_jwt(token.replace('Bearer ', ''), JWT_SECRET)
    if not user:
        return {
            'statusCode': 403,
            'headers': CORS_HEADERS,
            'body': json.dumps({ 'message': 'Invalid token' })
        }

    params = event.get('queryStringParameters') or {}
    activity_id = params.get('activityId')
    user_id = user.get('userId')

    if not activity_id or not user_id:
        return {
            'statusCode': 400,
            'headers': CORS_HEADERS,
            'body': json.dumps({ 'message': 'Missing activityId or userId' })
        }

    table = dynamodb.Table(TABLE_NAME)

    try:
        response = table.get_item(Key={
            'activityId': activity_id,
            'userId': user_id
        })

        item = response.get('Item')
        if not item:
            return {
                'statusCode': 404,
                'headers': CORS_HEADERS,
                'body': json.dumps({ 'message': 'Result not found' })
            }

        result = {
            'name': item.get('activityName', 'Untitled'),
            'correct': item.get('score', 0),
            'total': item.get('total', 0),
            'skills': json.loads(item.get('skills', '[]')) if isinstance(item.get('skills'), str) else item.get('skills', []),
            'passed': item.get('passed', True)
        }

        return {
            'statusCode': 200,
            'headers': CORS_HEADERS,
            'body': json.dumps(convert(result))
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'headers': CORS_HEADERS,
            'body': json.dumps({ 'message': 'Server error', 'error': str(e) })
        }