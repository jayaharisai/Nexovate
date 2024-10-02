from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User
from .serializers import RegisterSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer
from rest_framework_simplejwt.tokens import AccessToken
from .models import Account, Credential
from .serializers import AccountSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
import jwt
from rest_framework.decorators import api_view, permission_classes
from .serializers import AccountSerializer, CredentialsSerializer
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        
        # Validate the input data
        if serializer.is_valid():
            # Save the user if the data is valid
            serializer.save()
            return Response({
                'message': 'User registered successfully.'
            }, status=status.HTTP_201_CREATED)

        # Return validation errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']

            # Create JWT token payload
            payload = {
                'user_id': user.id,
                'email': user.email,  # Optional: Include other user info
                'exp': datetime.utcnow() + timedelta(hours=10)  # Set expiration time
            }

            # Generate JWT token
            access_token = jwt.encode(payload, "srdfgesrgedrsfgedrfgerfg", algorithm='HS256')

            return Response({
                'access': access_token,  # Send back the JWT token
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
def decode_jwt(token):
    try:
        # Decode the token using the secret key
        payload = jwt.decode(token, "srdfgesrgedrsfgedrfgerfg", algorithms=['HS256'])
        return payload, None  # Return payload and no error
    except jwt.ExpiredSignatureError:
        return None, Response({"detail": "Token has expired."}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError:
        return None, Response({"detail": "Invalid token."}, status=status.HTTP_401_UNAUTHORIZED)

class CreateAccountView(APIView):
    def post(self, request):
        # Decode the token to get user ID
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return Response({"error": "Authorization header is missing or invalid."}, status=status.HTTP_401_UNAUTHORIZED)
        
        token = auth_header.split(' ')[1]
        decoded_payload, error_response = decode_jwt(token)

        print(decoded_payload)
        

        if error_response:
            return error_response
        
        user_id = decoded_payload['user_id']
        data = request.data.copy()
        data['user_id'] = user_id  # Set the user ID from the token

        serializer = AccountSerializer(data=data)
        if serializer.is_valid():
            account = serializer.save()
            return Response(AccountSerializer(account).data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CreateCredentialsView(APIView):
    def post(self, request):
        # Decode the token to get user ID
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return Response({"error": "Authorization header is missing or invalid."}, status=status.HTTP_401_UNAUTHORIZED)
        
        token = auth_header.split(' ')[1]
        decoded_payload, error_response = decode_jwt(token)

        if error_response:
            return error_response
        
        user_id = decoded_payload['user_id']
        data = request.data.copy()
        data['user_id'] = user_id  # Set the user ID from the token

        # Ensure the account exists
        account_id = data.get('account')
        if not Account.objects.filter(id=account_id, user_id=user_id).exists():
            return Response({"error": "Account not found or does not belong to user."}, status=status.HTTP_404_NOT_FOUND)

        serializer = CredentialsSerializer(data=data)
        if serializer.is_valid():
            credentials = serializer.save()
            return Response(CredentialsSerializer(credentials).data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class GetAccountsView(APIView):
    def get(self, request):
        # Decode the token to get user ID
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return Response({"error": "Authorization header is missing or invalid."}, status=status.HTTP_401_UNAUTHORIZED)

        token = auth_header.split(' ')[1]
        decoded_payload, error_response = decode_jwt(token)

        if error_response:
            return error_response
        
        user_id = decoded_payload['user_id']  # Get user ID from decoded token

        # Get accounts associated with the user ID
        accounts = Account.objects.filter(user_id=user_id)

        # Create a response structure to include accounts with their credentials
        accounts_data = []
        for account in accounts:
            credentials = Credential.objects.filter(account=account)  # Get credentials for the current account
            credentials_data = [
                {
                    'id': cred.id,
                    'aws_access_key': cred.aws_access_key,
                    'aws_secret_key': cred.aws_secret_key,
                    'region': cred.region,
                    'created_at': cred.created_at,
                    "is_active": cred.is_active
                }
                for cred in credentials
            ]
            accounts_data.append({
                'id': account.id,
                'account_name': account.account_name,
                'created_at': account.created_at,
                'credentials': credentials_data,
            })

        return Response(accounts_data, status=status.HTTP_200_OK)
    

class DeleteCredentialsView(APIView):
    def delete(self, request, pk):
        # Decode the token to get user ID
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return Response({"error": "Authorization header is missing or invalid."}, status=status.HTTP_401_UNAUTHORIZED)

        token = auth_header.split(' ')[1]
        decoded_payload, error_response = decode_jwt(token)

        if error_response:
            return error_response
        
        user_id = decoded_payload['user_id']

        try:
            # Get the credential object
            credential = Credential.objects.get(pk=pk, account__user_id=user_id)
            credential.delete()
            return Response({"message": "Credential deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

        except Credential.DoesNotExist:
            return Response({"error": "Credential not found or does not belong to user."}, status=status.HTTP_404_NOT_FOUND)


class EditCredentialsView(APIView):
    def put(self, request, pk):
        # Decode the token to get user ID
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return Response({"error": "Authorization header is missing or invalid."}, status=status.HTTP_401_UNAUTHORIZED)

        token = auth_header.split(' ')[1]
        decoded_payload, error_response = decode_jwt(token)

        if error_response:
            return error_response
        
        user_id = decoded_payload['user_id']

        try:
            # Get the credential object
            credential = Credential.objects.get(pk=pk, account__user_id=user_id)

            # Update the credential data
            serializer = CredentialsSerializer(credential, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Credential.DoesNotExist:
            return Response({"error": "Credential not found or does not belong to user."}, status=status.HTTP_404_NOT_FOUND)
        

@api_view(['PUT'])
def toggle_active_credential(request, credential_id):
    try:
        # Find the credential by ID
        credential = Credential.objects.get(id=credential_id)

        # If this credential is not already active, deactivate all others for the same account
        if not credential.is_active:
            # Deactivate any currently active credentials for this account
            Credential.objects.filter(account=credential.account).update(is_active=False)

            # Activate this credential
            credential.is_active = True
        else:
            # If this credential is already active, deactivate it (toggle off)
            credential.is_active = False
        
        credential.save()

        return Response({"message": "Credential status updated successfully."}, status=status.HTTP_200_OK)

    except Credential.DoesNotExist:
        # If no credential is found for the given ID, return a 404 error
        return Response({"error": "Credential not found."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        # Catch any other exceptions and return a 500 error with the exception message
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    


import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

@api_view(['POST'])
def validate_aws_credentials(request):
    data = request.data
    aws_access_key = data.get('aws_access_key')
    aws_secret_key = data.get('aws_secret_key')
    region = data.get('region')

    # Validate input data
    if not aws_access_key or not aws_secret_key or not region:
        return Response({'error': 'AWS Access Key, Secret Key, and Region are required.'}, status=status.HTTP_400_BAD_REQUEST)

    # Create a session with the provided credentials
    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        # Attempt to list S3 buckets to validate the credentials
        s3 = session.client('s3')
        s3.list_buckets()
        return Response({'message': 'AWS credentials are valid.'}, status=status.HTTP_200_OK)

    except NoCredentialsError:
        return Response({'error': 'No valid AWS credentials provided.'}, status=status.HTTP_401_UNAUTHORIZED)

    except PartialCredentialsError:
        return Response({'error': 'Incomplete AWS credentials provided.'}, status=status.HTTP_401_UNAUTHORIZED)

    except ClientError as e:
        # Catch specific AWS service errors
        return Response({'error': str(e)}, status=status.HTTP_401_UNAUTHORIZED)

    except Exception as e:
        return Response({'error': 'An error occurred: ' + str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class UserAccountsView(APIView):
    def get(self, request):
        # Decode the token to get user ID
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return Response({"error": "Authorization header is missing or invalid."}, status=status.HTTP_401_UNAUTHORIZED)

        token = auth_header.split(' ')[1]
        decoded_payload, error_response = decode_jwt(token)

        if error_response:
            return error_response

        user_id = decoded_payload['user_id']

        # Fetch all accounts associated with this user
        accounts = Account.objects.filter(user_id=user_id)

        if not accounts.exists():
            return Response({"message": "No accounts found for this user."}, status=status.HTTP_404_NOT_FOUND)

        # Prepare the response data to include account and is_status=True credentials
        account_data = []

        for account in accounts:
            # Filter credentials for the account where is_status is True
            credentials = Credential.objects.filter(account=account, is_active=True)

            # Serialize account and its associated active credentials
            account_serializer = AccountSerializer(account)
            credentials_serializer = CredentialsSerializer(credentials, many=True)

            account_data.append({
                "account": account_serializer.data,
                "active_credentials": credentials_serializer.data
            })

        return Response(account_data, status=status.HTTP_200_OK)

class GetEC2InstancesView(APIView):
    def post(self, request):
        # Extract AWS credentials from the request
        aws_access_key = request.data.get("aws_access_key")
        aws_secret_key = request.data.get("aws_secret_key")
        region = request.data.get("region", "us-east-1")  # Default to us-east-1 if not provided

        # Validate input
        if not aws_access_key or not aws_secret_key:
            return Response({"error": "AWS Access Key and Secret Access Key are required."}, 
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create a session with AWS credentials
            session = boto3.Session(
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )

            ec2_client = session.client("ec2")

            # Get information about EC2 instances
            response = ec2_client.describe_instances()
            instances = []
            for reservation in response['Reservations']:
                instances.extend(reservation['Instances'])

            # Calculate required metrics
            total_instances = len(instances)
            running_instances = [i for i in instances if i['State']['Name'] == 'running']
            stopped_instances = [i for i in instances if i['State']['Name'] == 'stopped']

            # Count of powered on and powered off instances
            powered_on_count = len(running_instances)
            powered_off_count = len(stopped_instances)

            # Count of instances running by region
            instances_by_region = {region: powered_on_count}

            # Distribution of EC2 instance types
            instance_types_distribution = {}
            for instance in instances:
                instance_type = instance['InstanceType']
                if instance_type in instance_types_distribution:
                    instance_types_distribution[instance_type] += 1
                else:
                    instance_types_distribution[instance_type] = 1

            # Prepare response data
            response_data = {
                "total_instances": total_instances,
                "powered_on_instances": powered_on_count,
                "powered_off_instances": powered_off_count,
                "instances_by_region": instances_by_region,
                "instance_types_distribution": instance_types_distribution
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except (NoCredentialsError, PartialCredentialsError):
            return Response({"error": "Invalid AWS credentials provided."}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

# views.py

from rest_framework.decorators import api_view
from rest_framework.response import Response
import boto3
from botocore.exceptions import ClientError

from rest_framework.decorators import api_view
from rest_framework.response import Response
import boto3
from botocore.exceptions import ClientError

@api_view(['POST'])
def GetEC2InstanceStatus(request):
    aws_access_key = request.data.get('aws_access_key')
    aws_secret_key = request.data.get('aws_secret_key')
    region = request.data.get('region')

    # Create EC2 client
    ec2_client = boto3.client(
        'ec2',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=region
    )

    try:
        # Fetch the list of instances
        response = ec2_client.describe_instances()
        instances_data = {
            'running': [],
            'stopping': [],
            'starting': [],
            'stopped': [],
        }

        # Loop through instances and categorize by state
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                state = instance['State']['Name']
                instance_info = {
                    'instance_id': instance['InstanceId'],
                    'instance_type': instance['InstanceType'],
                    'public_ip': instance.get('PublicIpAddress', 'N/A'),
                    'private_ip': instance.get('PrivateIpAddress', 'N/A'),
                    'name': 'N/A'  # Default value if name tag doesn't exist
                }

                # Fetch instance name from tags
                if 'Tags' in instance:
                    for tag in instance['Tags']:
                        if tag['Key'] == 'Name':
                            instance_info['name'] = tag['Value']
                            break  # No need to continue checking tags

                # Categorize instances based on their state
                if state == 'running':
                    instances_data['running'].append(instance_info)
                elif state == 'stopping':
                    instances_data['stopping'].append(instance_info)
                elif state == 'pending':  # 'starting' corresponds to 'pending' in EC2
                    instances_data['starting'].append(instance_info)
                elif state == 'stopped':
                    instances_data['stopped'].append(instance_info)

        return Response(instances_data)

    except ClientError as e:
        return Response({'error': str(e)}, status=400)

    except Exception as e:
        return Response({'error': 'An error occurred'}, status=500)


@api_view(['POST'])
def start_ec2_instance(request):
    # Extract the instance ID from the request body
    instance_id = request.data.get('instance_id')
    aws_access_key = request.data.get('aws_access_key')
    aws_secret_key = request.data.get('aws_secret_key')
    region = request.data.get('region')

    if not instance_id:
        return Response({"error": "Instance ID is required."}, status=status.HTTP_400_BAD_REQUEST)

    # Start the EC2 instance
    try:
        ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        ec2_client.start_instances(InstanceIds=[instance_id])
        return Response({"message": "Instance started successfully."}, status=status.HTTP_200_OK)

    except ClientError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def stop_ec2_instance(request):
    # Extract the instance ID from the request body
    instance_id = request.data.get('instance_id')
    aws_access_key = request.data.get('aws_access_key')
    aws_secret_key = request.data.get('aws_secret_key')
    region = request.data.get('region')

    if not instance_id:
        return Response({"error": "Instance ID is required."}, status=status.HTTP_400_BAD_REQUEST)

    # Stop the EC2 instance
    try:
        ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        ec2_client.stop_instances(InstanceIds=[instance_id])
        return Response({"message": "Instance stopped successfully."}, status=status.HTTP_200_OK)

    except ClientError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)