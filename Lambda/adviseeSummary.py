import json
import os
import boto3
import base64
import hmac
import hashlib
from boto3.dynamodb.conditions import Key
import time

SECRET = os.environ.get('JWT_SECRET', 'default-secret')
TABLE_SUMMARY = os.environ.get('TABLE_SUMMARY', 'StudentSummary')
TABLE_SKILLS = os.environ.get('TABLE_SKILLS', 'Skills')
TABLE_SUBMISSIONS = os.environ.get('TABLE_SUBMISSIONS', 'Submissions')
TABLE_ACTIVITIES = os.environ.get('TABLE_ACTIVITIES', 'Activities')

dynamodb = boto3.resource('dynamodb')
summary_table = dynamodb.Table(TABLE_SUMMARY)
skills_table = dynamodb.Table(TABLE_SKILLS)
subs_table = dynamodb.Table(TABLE_SUBMISSIONS)
acts_table = dynamodb.Table(TABLE_ACTIVITIES)

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

def lambda_handler(event, context):
    token = event.get('headers', {}).get('Authorization') or event.get('headers', {}).get('authorization')
    if not token or not token.startswith('Bearer '):
        return {"statusCode": 401, "body": json.dumps({"message": "Missing or invalid token"})}

    user = decode_jwt(token.replace('Bearer ', ''), SECRET)
    if not user or user.get('role') != 'advisor':
        return {"statusCode": 403, "body": json.dumps({"message": "Access denied"})}

    try:
        response = summary_table.scan()
        students = []
        for item in response.get('Items', []):
            students.append({
                "studentId": item.get("studentId"),
                "name": item.get("name"),
                "totalActivities": int(item.get("totalActivities", 0))
            })

        return {
            "statusCode": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps(students)
        }
    except Exception as e:
        print("ERROR in /advisee-summary:", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Failed to load advisee summary", "error": str(e)})
        }