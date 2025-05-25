import json
import os
import base64
import hmac
import hashlib
import boto3
from boto3.dynamodb.conditions import Key

SECRET = os.environ.get('JWT_SECRET')
TABLE_SKILLS = os.environ.get('TABLE_SKILLS', 'Skills')
TABLE_SUBMISSIONS = os.environ.get('TABLE_SUBMISSIONS', 'Submissions')

ddb = boto3.resource('dynamodb')
skills_table = ddb.Table(TABLE_SKILLS)
subs_table = ddb.Table(TABLE_SUBMISSIONS)

def decode_jwt(token, secret):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        msg = f"{header}.{payload}".encode()
        expected_sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        ).rstrip(b'=').decode()
        if expected_sig != sig:
            return None
        return json.loads(base64.urlsafe_b64decode(payload + '==').decode())
    except:
        return None

def lambda_handler(event, context):
    headers = event.get('headers', {})
    token = headers.get('Authorization') or headers.get('authorization')
    if not token or not token.startswith('Bearer '):
        return { 'statusCode': 401, 'body': json.dumps({ 'message': 'Missing token' }) }

    user = decode_jwt(token.replace('Bearer ', ''), SECRET)
    if not user or user.get('role') != 'student':
        return { 'statusCode': 403, 'body': json.dumps({ 'message': 'Access denied' }) }

    user_id = user.get('userId')

    try:
        # 🎯 ดึงจำนวนกิจกรรมทั้งหมดที่เข้าร่วม
        subs = subs_table.query(
            IndexName='userId-index',
            KeyConditionExpression=Key('userId').eq(user_id)
        )
        total_activities = len(subs.get('Items', []))

        # 💡 ดึง skill ทั้งหมดของ userId
        skills = skills_table.query(
            IndexName='userId-index',
            KeyConditionExpression=Key('userId').eq(user_id)
        ).get('Items', [])

        soft_keywords = ['Teamwork', 'Communication', 'Leadership', 'Problem-solving', 'Creativity', 'Adaptability']
        soft_skills = {}
        hard_skills = {}

        for item in skills:
            name = item.get('skillName')
            if name in soft_keywords:
                soft_skills[name] = soft_skills.get(name, 0) + 1
            else:
                hard_skills[name] = hard_skills.get(name, 0) + 1

        return {
            'statusCode': 200,
            'headers': { 'Access-Control-Allow-Origin': '*' },
            'body': json.dumps({
                'totalActivities': total_activities,
                'softSkills': soft_skills,
                'hardSkills': hard_skills
            })
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'headers': { 'Access-Control-Allow-Origin': '*' },
            'body': json.dumps({ 'message': 'Error loading summary', 'error': str(e) })
        }