import json
import boto3
import os

dynamodb = boto3.client('dynamodb')
TABLE = os.environ.get('TABLE_ACTIVITIES', 'Activities')

def lambda_handler(event, context):
    activity_id = event['pathParameters']['id']

    try:
        result = dynamodb.get_item(
            TableName=TABLE,
            Key={'activityId': {'S': activity_id}}
        )

        if 'Item' not in result:
            return {
                'statusCode': 404,
                'headers': {'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'message': 'Activity not found'})
            }

        item = {k: list(v.values())[0] for k, v in result['Item'].items()}

        return {
            'statusCode': 200,
            'headers': {'Access-Control-Allow-Origin': '*'},
            'body': json.dumps(item)
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'message': 'Error fetching activity', 'error': str(e)})
        }
