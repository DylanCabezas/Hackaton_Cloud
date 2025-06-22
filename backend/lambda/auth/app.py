import os
import json
import time
import boto3
from jose import jwt
from botocore.exceptions import ClientError

# Configuración - Reemplaza con tus valores de AWS Educate
SECRET_NAME = "UTECDiagramSecret" 
SECRET_KEY = "your-secret-key-here"  
TOKEN_EXPIRATION = 3600  

dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('UTECDiagramUsers')

def lambda_handler(event, context):
    try:
        body = json.loads(event['body'])
        email = body['email']
        password = body['password']
        is_signup = event.get('path', '').endswith('/signup')
        
        if is_signup:
            # Registro de usuario
            if body.get('confirmPassword') != password:
                return error_response("Las contraseñas no coinciden", 400)
                
            try:
                users_table.put_item(
                    Item={
                        'email': email,
                        'password': password,  # En producción usarías bcrypt
                        'createdAt': int(time.time())
                    },
                    ConditionExpression='attribute_not_exists(email)'
                )
                return success_response({"message": "Usuario registrado exitosamente"})
            except ClientError as e:
                if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                    return error_response("El usuario ya existe", 400)
                raise
        else:
            # Login
            response = users_table.get_item(Key={'email': email})
            user = response.get('Item')
            
            if not user or user['password'] != password:
                return error_response("Credenciales inválidas", 401)
                
            token = jwt.encode({
                'sub': email,
                'exp': time.time() + TOKEN_EXPIRATION
            }, SECRET_KEY, algorithm='HS256')
            
            return success_response({"token": token})
            
    except Exception as e:
        return error_response(str(e), 500)

def success_response(data):
    return {
        'statusCode': 200,
        'body': json.dumps(data),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }

def error_response(message, code):
    return {
        'statusCode': code,
        'body': json.dumps({"error": message}),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }