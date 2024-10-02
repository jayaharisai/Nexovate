from django.urls import path
from .views import RegisterView, LoginView, UserAccountsView, GetEC2InstancesView, GetEC2InstanceStatus
from .views import CreateAccountView, CreateCredentialsView, GetAccountsView, DeleteCredentialsView, EditCredentialsView, toggle_active_credential, validate_aws_credentials,start_ec2_instance, stop_ec2_instance


urlpatterns = [
    path('register', RegisterView.as_view(), name='register'),
    path('login', LoginView.as_view(), name='login'),
    path('create-account', CreateAccountView.as_view(), name='create-account'),
    path('create-credentials', CreateCredentialsView.as_view(), name='create-credentials'),
    path('accounts', GetAccountsView.as_view(), name='get_accounts'),
    path('delete-credential/<int:pk>', DeleteCredentialsView.as_view(), name='delete_credentials'),
    path('edit-credential/<int:pk>', EditCredentialsView.as_view(), name='edit_credentials'),
    path('toggle-active-credential/<int:credential_id>', toggle_active_credential, name='toggle-active-credential'),
    path('validate-aws-credentials', validate_aws_credentials, name='validate_aws_credentials'),
     path('user-accounts/', UserAccountsView.as_view(), name='user-accounts'),
     path('GetEC2InstancesView', GetEC2InstancesView.as_view(), name='GetEC2InstancesView'),
     path('GetEC2InstanceStatus', GetEC2InstanceStatus, name='get_ec2_instance_status'),
     path('start-ec2-instance/', start_ec2_instance, name='start-ec2-instance'),
    path('stop-ec2-instance/', stop_ec2_instance, name='stop-ec2-instance'),

]