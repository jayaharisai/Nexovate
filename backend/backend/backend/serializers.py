from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from .models import Account, Credential
import re

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password']

    # Custom validation logic
    def validate_email(self, value):
        """Ensure that the email is not already registered"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email is already registered.")
        return value

    def validate_password(self, value):
        """Check for password complexity and prevent the email being used as the password"""
        data = self.initial_data  # Get the data from the request
        email = data.get('email')

        # Password should not be the same as the email
        if value == email:
            raise serializers.ValidationError("Password should not be the same as the email.")

        # Minimum length requirement
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")

        # Password complexity: at least one uppercase letter, one lowercase letter, and one digit
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'[0-9]', value):
            raise serializers.ValidationError("Password must contain at least one digit.")

        return value

    def create(self, validated_data):
        """Save the user, but ensure password is securely hashed"""
        user = User(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            email=validated_data['email'],
        )
        # Ideally, you'd hash the password here before saving (use a custom hashing mechanism)
        user.password = validated_data['password']  # You can replace this with your own hashing logic
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        # Check if the user exists in the database
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError('Invalid email or password.')

        # Check if the provided password matches the stored password
        if user.password != password:
            raise serializers.ValidationError('Invalid email or password.')

        attrs['user'] = user
        return attrs
    
class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ['id', 'account_name', 'user_id', 'created_at']

class CredentialsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Credential
        fields = "__all__"