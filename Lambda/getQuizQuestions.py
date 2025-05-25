import json
import os
import base64
import hmac
import hashlib
import boto3

dynamodb = boto3.client('dynamodb')
TABLE = os.environ.get('TABLE_QUIZ', 'QuizQuestions')
SECRET = os.environ.get('JWT_SECRET', 'default-secret')

def decode_jwt(token, secret):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header_b64, payload_b64, signature_b64 = parts
        msg = f"{header_b64}.{payload_b64}".encode()
        sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
        if sig_b64 != signature_b64:
            return None
        payload_json = base64.urlsafe_b64decode(payload_b64 + '==')
        payload = json.loads(payload_json.decode())
        return payload
    except:
        return None

def lambda_handler(event, context):
    headers = event.get('headers', {})
    token = headers.get('Authorization') or headers.get('authorization')

    if not token or not token.startswith('Bearer '):
        return {
            "statusCode": 401,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"message": "Missing or invalid token"})
        }

    token = token.replace('Bearer ', '')
    user = decode_jwt(token, SECRET)
    if not user or user.get('role') != 'student':
        return {
            "statusCode": 403,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"message": "Access denied"})
        }

    activity_id = event.get('queryStringParameters', {}).get('activityId')
    if not activity_id:
        return {
            "statusCode": 400,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"message": "Missing activityId"})
        }

    try:
        result = dynamodb.query(
            TableName=TABLE,
            KeyConditionExpression="activityId = :aid",
            ExpressionAttributeValues={":aid": {"S": activity_id}}
        )

        items = []
        for item in result.get('Items', []):
            question = {
                'id': item['questionId']['S'],
                'question': item['question']['S'],
                'options': [opt['S'] for opt in item['options']['L']],  # ✅ แก้ตรงนี้ให้เป็น string array
                'relatedSkill': item['relatedSkill']['S']
            }
            items.append(question)

        return {
            "statusCode": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps(items)
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Error loading quiz", "error": str(e)})
        }
