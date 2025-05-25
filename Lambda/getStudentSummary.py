import json
import os
import base64
import hmac
import hashlib
from collections import defaultdict
import boto3

dynamodb = boto3.client('dynamodb')
TABLE_SUBMISSIONS = os.environ['TABLE_SUBMISSIONS']
TABLE_SKILLS = os.environ['TABLE_SKILLS']
SECRET = os.environ['JWT_SECRET']

SOFT_SKILLS_SET = set([
    "Teamwork", "Communication", "Leadership", "Problem-solving",
    "Humility", "Adaptability", "Creativity", "Innovation"
])

def decode_jwt(token, secret):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        msg = f"{header}.{payload}".encode()
        sig_check = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig_check).rstrip(b'=').decode()
        if sig_b64 != sig:
            return None
        payload_json = base64.urlsafe_b64decode(payload + '==')
        return json.loads(payload_json.decode())
    except:
        return None

def lambda_handler(event, context):
    headers = event.get('headers', {})
    token = headers.get('Authorization') or headers.get('authorization')

    if not token or not token.startswith('Bearer '):
        return {
            "statusCode": 401,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"message": "Unauthorized"})
        }

    user = decode_jwt(token.replace('Bearer ', ''), SECRET)
    if not user:
        return {
            "statusCode": 403,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"message": "Invalid token"})
        }

    user_id = user.get('userId')

    try:
        # 1. Total Activities
        submission_result = dynamodb.query(
            TableName=TABLE_SUBMISSIONS,
            IndexName='userId-index',
            KeyConditionExpression='userId = :uid',
            ExpressionAttributeValues={':uid': {'S': user_id}}
        )
        total_activities = len(submission_result.get('Items', []))

        # 2. Skills (split soft vs hard)
        skills_result = dynamodb.query(
            TableName=TABLE_SKILLS,
            KeyConditionExpression='userId = :uid',
            ExpressionAttributeValues={':uid': {'S': user_id}}
        )

        hard_skills = defaultdict(int)
        soft_skills = defaultdict(int)

        for item in skills_result.get('Items', []):
            skill = item['skillName']['S']
            if skill in SOFT_SKILLS_SET:
                soft_skills[skill] += 1
            else:
                hard_skills[skill] += 1

        return {
            "statusCode": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({
                "totalActivities": total_activities,
                "hardSkills": dict(hard_skills),
                "softSkills": dict(soft_skills)
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Error fetching summary", "error": str(e)})
        }
