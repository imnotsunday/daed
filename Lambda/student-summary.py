import time
import json
import os
import boto3
import base64
import hmac
import hashlib
from boto3.dynamodb.conditions import Key

# 🔐 JWT secret from environment
SECRET = os.environ.get('JWT_SECRET', 'default-secret')

# 📦 DynamoDB table names from environment
TABLE_SKILLS = os.environ.get('TABLE_SKILLS', 'Skills')
TABLE_SUBMISSIONS = os.environ.get('TABLE_SUBMISSIONS', 'Submissions')
TABLE_ACTIVITIES = os.environ.get('TABLE_ACTIVITIES', 'Activities')
TABLE_SUMMARY = os.environ.get('TABLE_SUMMARY', 'StudentSummary')

# 📚 DynamoDB client setup
ddb = boto3.resource('dynamodb')
skills_table = ddb.Table(TABLE_SKILLS)
subs_table = ddb.Table(TABLE_SUBMISSIONS)
acts_table = ddb.Table(TABLE_ACTIVITIES)
sum_table = ddb.Table(TABLE_SUMMARY)

# 🔐 JWT decode helper
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

# 🚀 Lambda entry point
def lambda_handler(event, context):
    token = event.get('headers', {}).get('Authorization') or event.get('headers', {}).get('authorization')
    if not token or not token.startswith('Bearer '):
        return {"statusCode": 401, "body": json.dumps({"message": "Missing or invalid token"})}

    user = decode_jwt(token.replace('Bearer ', ''), SECRET)
    if not user or user.get('role') != 'advisor':
        return {"statusCode": 403, "body": json.dumps({"message": "Access denied"})}

    params = event.get('queryStringParameters') or {}
    student_id = params.get('studentId')
    if not student_id:
        return {"statusCode": 400, "body": json.dumps({"message": "Missing studentId"})}

    try:
        # 🧑‍🎓 Get student name
        name = student_id
        try:
            summary = sum_table.get_item(Key={'studentId': student_id}).get('Item', {})
            name = summary.get('name', student_id)
        except Exception as lookup_err:
            print("Student summary lookup error:", str(lookup_err))

        # 💡 Get skills
        soft, hard = [], []
        response = skills_table.query(
            IndexName='userId-index',
            KeyConditionExpression=Key('userId').eq(student_id)
        )
        for item in response.get('Items', []):
            skill = item.get('skillName')
            if skill in ["Teamwork", "Communication", "Leadership", "Problem-solving", "Humility", "Adaptability", "Creativity", "Innovation"]:
                soft.append(skill)
            else:
                hard.append(skill)

        # 📝 Get quiz submissions & activity info
        result = subs_table.query(
            IndexName='userId-index',
            KeyConditionExpression=Key('userId').eq(student_id)
        )
        activities = []
        for s in result.get('Items', []):
            act_id = s['activityId']
            act_info = acts_table.get_item(Key={'activityId': act_id}).get('Item', {})
            activities.append({
                "activityId": act_id,
                "name": act_info.get('name', ''),
                "score": int(s.get('score', 0)),
                "total": int(s.get('total', 10)),
                "skills": json.loads(s.get('skills', '[]')),
                "proofUrl": s.get('proofUrl', '')
            })

        return {
            "statusCode": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({
                "studentId": student_id,
                "name": name,
                "totalActivities": len(activities),
                "softSkills": soft,
                "hardSkills": hard,
                "activities": activities
            })
        }

    except Exception as e:
        print("ERROR in /student-summary:", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Failed to get student summary", "error": str(e)})
        }
