import os
import json
import uuid
import base64
import re
import time
import boto3
from io import BytesIO
from jose import jwt

# Configuración para AWS Educate - REEMPLAZA CON TUS VALORES
SECRET_KEY = "tu_clave_secreta_super_segura"  # Usa una clave más segura en producción
BUCKET_NAME = os.environ.get('BUCKET_NAME', 'utec-diagram-bucket')
MAX_CODE_LENGTH = 5000  # Límite para prevenir abuso
TOKEN_EXPIRATION = 3600  # 1 hora en segundos

# Clientes AWS
s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('UTECDiagramUsers')
diagrams_table = dynamodb.Table('UTECDiagramDiagrams')

def lambda_handler(event, context):
    try:
        # Determinar la ruta solicitada
        path = event.get('path', '')
        
        if path == '/login':
            return handle_login(event)
        elif path == '/signup':
            return handle_signup(event)
        elif path == '/generate':
            return handle_generate(event)
        else:
            return error_response("Ruta no encontrada", 404)
            
    except Exception as e:
        return error_response(f"Error interno: {str(e)}", 500)

def handle_login(event):
    body = json.loads(event['body'])
    email = body['email']
    password = body['password']
    
    response = users_table.get_item(Key={'email': email})
    user = response.get('Item')
    
    if not user or user['password'] != password:
        return error_response("Credenciales inválidas", 401)
        
    token = jwt.encode({
        'sub': email,
        'exp': time.time() + TOKEN_EXPIRATION
    }, SECRET_KEY, algorithm='HS256')
    
    return success_response({"token": token})

def handle_signup(event):
    body = json.loads(event['body'])
    email = body['email']
    password = body['password']
    confirm_password = body.get('confirmPassword', '')
    
    if password != confirm_password:
        return error_response("Las contraseñas no coinciden", 400)
    
    try:
        users_table.put_item(
            Item={
                'email': email,
                'password': password,  # En producción usar bcrypt
                'createdAt': int(time.time())
            },
            ConditionExpression='attribute_not_exists(email)'
        )
        return success_response({"message": "Usuario registrado exitosamente"})
    except users_table.meta.client.exceptions.ConditionalCheckFailedException:
        return error_response("El usuario ya existe", 400)

def handle_generate(event):
    # Verificar autenticación
    auth_header = event.get('headers', {}).get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return error_response("Token de acceso requerido", 401)
    
    token = auth_header.split(' ')[1]
    try:
        claims = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_email = claims['sub']
    except jwt.ExpiredSignatureError:
        return error_response("Token expirado", 401)
    except jwt.JWTError:
        return error_response("Token inválido", 401)
    
    # Procesar solicitud de generación
    body = json.loads(event['body'])
    code = body.get('code', '')[:MAX_CODE_LENGTH]
    diagram_type = body.get('type', 'aws')
    
    if not code:
        return error_response("Código de diagrama requerido", 400)
    
    try:
        if diagram_type == 'aws':
            image_data = generate_aws_diagram(code)
        elif diagram_type == 'er':
            image_data = generate_er_diagram(code)
        elif diagram_type == 'json':
            image_data = generate_json_diagram(code)
        else:
            return error_response("Tipo de diagrama no soportado", 400)
        
        # Guardar en S3 y DynamoDB
        diagram_id = str(uuid.uuid4())
        timestamp = int(time.time())
        
        # Guardar código
        code_key = f"code/{user_email}/{diagram_id}.txt"
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=code_key,
            Body=code.encode('utf-8'),
            ContentType='text/plain'
        )
        
        # Guardar imagen
        image_key = f"images/{user_email}/{diagram_id}.png"
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=image_key,
            Body=image_data,
            ContentType='image/png'
        )
        
        # Guardar metadatos
        diagrams_table.put_item(Item={
            'diagramId': diagram_id,
            'userId': user_email,
            'type': diagram_type,
            'createdAt': timestamp,
            'codeS3Key': code_key,
            'imageS3Key': image_key
        })
        
        return success_response({
            "diagramUrl": f"https://{BUCKET_NAME}.s3.amazonaws.com/{image_key}",
            "diagramId": diagram_id
        })
        
    except ValueError as e:
        return error_response(str(e), 400)

def generate_aws_diagram(code):
    """Genera un diagrama de arquitectura AWS simplificado"""
    try:
        # Simulación sin usar la librería diagrams (problemas en Lambda)
        # En un entorno real, usarías: from diagrams import Diagram, ...
        
        # Parsear componentes AWS del código (ejemplo simple)
        services = set()
        for line in code.split('\n'):
            if 'ec2' in line.lower():
                services.add('EC2')
            if 'lambda' in line.lower():
                services.add('Lambda')
            if 'rds' in line.lower():
                services.add('RDS')
            if 's3' in line.lower():
                services.add('S3')
        
        if not services:
            services = ['EC2', 'RDS']  # Default
            
        # Generar SVG básico
        svg_services = ""
        for i, service in enumerate(services):
            y = 100 + i * 80
            svg_services += f"""
            <rect x="150" y="{y}" width="100" height="60" fill="#fff" stroke="#000" rx="5"/>
            <text x="200" y="{y+30}" text-anchor="middle" font-family="Arial">{service}</text>
            """
            if i > 0:
                svg_services += f"""
                <line x1="200" y1="{y}" x2="200" y2="{y-40}" stroke="#000" stroke-width="2"/>
                <polygon points="200,{y-40} 195,{y-30} 205,{y-30}" fill="#000"/>
                """
        
        svg_content = f"""
        <svg width="400" height="{180 + len(services)*80}" xmlns="http://www.w3.org/2000/svg">
            <rect width="100%" height="100%" fill="#f0f0f0"/>
            <text x="50%" y="30" text-anchor="middle" font-family="Arial" font-size="20">
                Diagrama AWS
            </text>
            {svg_services}
        </svg>
        """
        
        # Convertir a bytes como PNG (simulación)
        return base64.b64decode(svg_content.encode('utf-8'))
        
    except Exception as e:
        raise ValueError(f"Error generando diagrama AWS: {str(e)}")

def generate_er_diagram(code):
    """Genera un diagrama entidad-relación simplificado"""
    try:
        # Parsear entidades y relaciones
        entities = []
        relationships = []
        
        # Parseo simple (mejorar para producción)
        for line in code.split('\n'):
            line = line.strip()
            if line.startswith('entity:') or '->' in line:
                parts = [p.strip() for p in line.split(':')]
                if len(parts) >= 2:
                    entities.append(parts[1])
            elif '--' in line:  # Relación simple
                rel_parts = [p.strip() for p in line.split('--')]
                if len(rel_parts) >= 2:
                    relationships.append((rel_parts[0], rel_parts[1]))
        
        if not entities:
            entities = ['Usuario', 'Producto']
            relationships = [('Usuario', 'Producto')]
        
        # Generar SVG
        svg_entities = ""
        svg_relations = ""
        
        for i, entity in enumerate(entities):
            y = 100 + i * 100
            svg_entities += f"""
            <rect x="100" y="{y}" width="200" height="60" fill="#fff" stroke="#000" rx="5"/>
            <text x="200" y="{y+30}" text-anchor="middle" font-family="Arial">{entity}</text>
            """
        
        for i, (ent1, ent2) in enumerate(relationships[:3]):  # Máximo 3 relaciones para simplificar
            idx1 = entities.index(ent1) if ent1 in entities else 0
            idx2 = entities.index(ent2) if ent2 in entities else min(1, len(entities)-1)
            
            y1 = 130 + idx1 * 100
            y2 = 130 + idx2 * 100
            svg_relations += f"""
            <line x1="300" y1="{y1}" x2="300" y2="{y2}" stroke="#000" stroke-width="2"/>
            <text x="310" y="{(y1+y2)/2}" font-family="Arial" font-size="12">1-*</text>
            """
        
        svg_content = f"""
        <svg width="500" height="{150 + len(entities)*100}" xmlns="http://www.w3.org/2000/svg">
            <rect width="100%" height="100%" fill="#f0f0f0"/>
            <text x="50%" y="30" text-anchor="middle" font-family="Arial" font-size="20">
                Diagrama ER
            </text>
            {svg_entities}
            {svg_relations}
        </svg>
        """
        
        return base64.b64decode(svg_content.encode('utf-8'))
        
    except Exception as e:
        raise ValueError(f"Error generando diagrama ER: {str(e)}")

def generate_json_diagram(code):
    """Genera una visualización de estructura JSON"""
    try:
        # Intentar parsear el JSON
        try:
            data = json.loads(code)
        except json.JSONDecodeError:
            data = {"error": "JSON inválido", "original": code[:100] + "..."}
        
        # Generar representación visual simple
        items = []
        if isinstance(data, dict):
            items.extend(data.items())
        elif isinstance(data, list):
            items = [(f"Item {i}", val) for i, val in enumerate(data[:5])]  # Mostrar primeros 5
        
        svg_items = ""
        for i, (key, value) in enumerate(items[:5]):  # Máximo 5 items
            y = 100 + i * 40
            svg_items += f"""
            <rect x="100" y="{y}" width="300" height="30" fill="#fff" stroke="#000" rx="3"/>
            <text x="110" y="{y+20}" font-family="Arial" font-size="14">
                {key}: {str(value)[:30]}{'...' if len(str(value)) > 30 else ''}
            </text>
            """
        
        svg_content = f"""
        <svg width="500" height="{150 + len(items)*40}" xmlns="http://www.w3.org/2000/svg">
            <rect width="100%" height="100%" fill="#f0f0f0"/>
            <text x="50%" y="30" text-anchor="middle" font-family="Arial" font-size="20">
                Estructura JSON
            </text>
            {svg_items}
        </svg>
        """
        
        return base64.b64decode(svg_content.encode('utf-8'))
        
    except Exception as e:
        raise ValueError(f"Error generando diagrama JSON: {str(e)}")

def success_response(data):
    return {
        'statusCode': 200,
        'body': json.dumps(data),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }

def error_response(message, code=400):
    return {
        'statusCode': code,
        'body': json.dumps({'error': message}),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }