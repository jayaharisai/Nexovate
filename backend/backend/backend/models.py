from django.db import models

class User(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)  # Ensure unique email addresses
    password = models.CharField(max_length=255)  # Store the password securely

    def __str__(self):
        return self.email
    

class Account(models.Model):
    id = models.AutoField(primary_key=True)
    account_name = models.CharField(max_length=255)
    user_id = models.IntegerField()  # Assuming you're storing user ID as an integer
    created_at = models.DateTimeField(auto_now_add=True)

class Credential(models.Model):
    id = models.AutoField(primary_key=True)
    account = models.ForeignKey('Account', on_delete=models.CASCADE)  # Assuming this links to your Account model
    aws_access_key = models.CharField(max_length=255)
    aws_secret_key = models.CharField(max_length=255)
    region = models.CharField(max_length=100)
    is_active = models.BooleanField(default=False)
    user_id = models.IntegerField()  # or models.ForeignKey(User, ...) if you have a User model
    created_at = models.DateTimeField(auto_now_add=True)