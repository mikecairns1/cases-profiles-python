from flask import Flask, render_template, request, flash, redirect, url_for
import boto3
from functools import wraps
import json
import os
from cryptography.fernet import Fernet
from pathlib import Path
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Define paths for storing encrypted credentials
CONFIG_DIR = Path.home() / '.aws-profiles-gui'  # Store in user's home directory
KEY_FILE = CONFIG_DIR / 'key.bin'  # File to store encryption key
CREDS_FILE = CONFIG_DIR / 'credentials.enc'  # File to store encrypted credentials

def initialize_crypto():
    """Initialize or load encryption key for credential storage
    Creates a new key if one doesn't exist, otherwise loads existing key
    Returns: Fernet encryption object for encrypting/decrypting data
    """
    CONFIG_DIR.mkdir(exist_ok=True)
    
    if not KEY_FILE.exists():
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
    
    return Fernet(KEY_FILE.read_bytes())

def get_stored_credentials():
    """Retrieve and decrypt stored AWS credentials
    Returns: Dictionary containing:
        - access_key: AWS access key ID
        - secret_key: AWS secret access key
        - session_token: AWS session token (optional)
        - region: AWS region
    Returns default None values if no credentials exist or on error
    """
    crypto = initialize_crypto()
    
    if not CREDS_FILE.exists():
        return {
            'access_key': None,
            'secret_key': None,
            'session_token': None,
            'region': None
        }
    
    try:
        encrypted_data = CREDS_FILE.read_bytes()
        decrypted_data = crypto.decrypt(encrypted_data)
        return json.loads(decrypted_data)
    except Exception as e:
        print(f"Error reading credentials: {e}")
        return {
            'access_key': None,
            'secret_key': None,
            'session_token': None,
            'region': None
        }

def save_credentials(creds):
    """Encrypt and save AWS credentials to disk
    Args:
        creds: Dictionary containing AWS credentials to encrypt and store
    """
    crypto = initialize_crypto()
    encrypted_data = crypto.encrypt(json.dumps(creds).encode())
    CREDS_FILE.write_bytes(encrypted_data)

# Initialize credentials from secure storage
credentials = get_stored_credentials()

def require_credentials(f):
    """Decorator to ensure AWS credentials exist before accessing protected routes
    Redirects to credential input page if credentials are missing
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        global credentials
        credentials = get_stored_credentials()  # Refresh credentials
        if not all(credentials.values()):
            flash('Please set your AWS credentials first', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
def index():
    """Main page for credential management
    GET: Display credential input form
    POST: Save submitted credentials
    """
    global credentials
    if request.method == 'POST':
        new_credentials = {
            'access_key': request.form['access_key'],
            'secret_key': request.form['secret_key'],
            'session_token': request.form['session_token'],
            'region': request.form['region']
        }
        
        # Save to secure storage
        save_credentials(new_credentials)
        credentials = new_credentials
        
        flash('Credentials saved successfully!', 'success')
        return redirect(url_for('index'))
    
    # Refresh credentials from secure storage
    credentials = get_stored_credentials()
    return render_template('index.html', credentials=credentials)

@app.route('/profiles', methods=['GET'])
@require_credentials
def list_profiles():
    """List all Customer Profiles domains
    Requires valid AWS credentials
    Displays domains or shows error if API call fails
    """
    try:
        connect_client = boto3.client(
            'customer-profiles',
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            aws_session_token=credentials['session_token'],
            region_name=credentials['region']
        )
        
        response = connect_client.list_domains()
        return render_template('profiles.html', domains=response['Items'])
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Clear stored credentials"""
    if CREDS_FILE.exists():
        CREDS_FILE.unlink()
    global credentials
    credentials = get_stored_credentials()
    flash('Credentials cleared successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/search', methods=['GET'])
@require_credentials
def search_profiles():
    """Search for profiles within a specific domain
    Args (from query params):
        domain_name: Name of domain to search in
        search_term: Optional search string
        next_token: Optional pagination token
    Returns paginated search results or error message
    """
    domain_name = request.args.get('domain_name')
    search_term = request.args.get('search_term', '')
    next_token = request.args.get('next_token')
    
    if not domain_name:
        flash('Please select a domain', 'error')
        return redirect(url_for('list_profiles'))
    
    try:
        connect_client = boto3.client(
            'customer-profiles',
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            aws_session_token=credentials['session_token'],
            region_name=credentials['region']
        )
        
        search_params = {
            'DomainName': domain_name,
            'MaxResults': 20
        }
        
        if next_token:
            search_params['NextToken'] = next_token
            
        if search_term:
            # Use list_profile_objects for searching
            response = connect_client.list_profile_objects(
                DomainName=domain_name,
                MaxResults=20,
                NextToken=next_token if next_token else None
            )
        else:
            # List all profiles if no search term
            response = connect_client.list_profile_objects(
                DomainName=domain_name,
                MaxResults=20,
                NextToken=next_token if next_token else None
            )
        
        profiles = response.get('Items', [])
        next_token = response.get('NextToken')
        
        return render_template('search_results.html',
                             domain_name=domain_name,
                             search_term=search_term,
                             profiles=profiles,
                             next_token=next_token)
                             
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('list_profiles'))

@app.route('/profile/<domain_name>/<profile_id>')
@require_credentials
def profile_details(domain_name, profile_id):
    """Display detailed information for a specific customer profile
    Args:
        domain_name: Name of the domain containing the profile
        profile_id: Unique identifier for the profile
    Shows profile data or error message if profile not found
    """
    try:
        connect_client = boto3.client(
            'customer-profiles',
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            aws_session_token=credentials['session_token'],
            region_name=credentials['region']
        )
        
        # Search for the specific profile using _profileId
        response = connect_client.search_profiles(
            DomainName=domain_name,
            KeyName='_profileId',
            Values=[profile_id],
            MaxResults=1
        )
        
        # Get the first (and should be only) profile from the response
        profiles = response.get('Items', [])
        if not profiles:
            flash('Profile not found', 'error')
            return redirect(url_for('list_domain_profiles', domain_name=domain_name))
            
        profile = profiles[0]
        
        return render_template('profile_details.html',
                             domain_name=domain_name,
                             profile=profile)
                             
    except Exception as e:
        print(f"Error getting profile details: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('list_domain_profiles', domain_name=domain_name))

@app.route('/domain/<domain_name>')
@require_credentials
def domain_details(domain_name):
    """Show detailed information about a Customer Profiles domain
    Args:
        domain_name: Name of domain to display
    Includes:
        - Domain configuration
        - Object types defined in domain
        - Templates available for each object type
    """
    try:
        connect_client = boto3.client(
            'customer-profiles',
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            aws_session_token=credentials['session_token'],
            region_name=credentials['region']
        )
        
        # Get domain details
        domain_response = connect_client.get_domain(
            DomainName=domain_name
        )
        
        # Get object types for this domain
        object_types_response = connect_client.list_profile_object_types(
            DomainName=domain_name,
            MaxResults=100
        )
        
        # Get field info for each object type
        object_types = object_types_response.get('Items', [])
        for obj_type in object_types:
            try:
                # Note: Some domains might not support templates
                template_response = connect_client.list_profile_object_type_templates()
                templates = [t for t in template_response.get('Items', []) 
                           if t.get('ObjectTypeName') == obj_type['ObjectTypeName']]
                obj_type['Templates'] = templates
            except Exception as e:
                print(f"Error getting templates for {obj_type['ObjectTypeName']}: {str(e)}")
                obj_type['Templates'] = []
        
        # Remove ResponseMetadata from domain_response
        domain = {k: v for k, v in domain_response.items() if k != 'ResponseMetadata'}
        
        return render_template('domain_details.html',
                             domain=domain,
                             object_types=object_types)
                             
    except Exception as e:
        print(f"Error in domain_details: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('list_profiles'))

@app.route('/domain/<domain_name>/profiles')
@require_credentials
def list_domain_profiles(domain_name):
    try:
        connect_client = boto3.client(
            'customer-profiles',
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            aws_session_token=credentials['session_token'],
            region_name=credentials['region']
        )
        
        # Get parameters from request
        next_token = request.args.get('next_token')
        search_term = request.args.get('search', '').strip()
        search_field = request.args.get('search_field', '').strip()
        
        # Predefined searchable fields with display names
        available_fields = [
            {'key': '_fullName', 'display': 'Full Name'},
            {'key': '_phone', 'display': 'Phone'},
            {'key': '_email', 'display': 'Email'},
            {'key': '_account', 'display': 'Account'},
            {'key': '_profileId', 'display': 'Profile ID'}
        ]
        
        # Get profiles using search_profiles
        params = {
            'DomainName': domain_name,
            'MaxResults': 20
        }
        
        if next_token:
            params['NextToken'] = next_token
            
        if search_term and search_field:
            # Try searching with the selected field
            params['KeyName'] = search_field
            params['Values'] = [search_term]
            print(f"Search params: {params}")  # Debug print
            response = connect_client.search_profiles(**params)
        else:
            # If no search criteria, list all profiles
            params['KeyName'] = '_profileId'
            params['Values'] = ['*']
            print(f"List params: {params}")  # Debug print
            response = connect_client.search_profiles(**params)
            
        print(f"Response: {response}")  # Debug print
        
        return render_template('domain_profiles.html',
                             domain_name=domain_name,
                             profiles=response.get('Items', []),
                             next_token=response.get('NextToken'),
                             search_term=search_term,
                             search_field=search_field,
                             available_fields=available_fields)
                             
    except Exception as e:
        print(f"Error listing domain profiles: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('domain_details', domain_name=domain_name))

@app.route('/cases')
@require_credentials
def list_cases():
    """List Connect Cases with optional filtering
    Query params:
        next_token: Pagination token
        search_term: Text to search for
        status: Filter by case status
        domain_id: Specific domain to show cases from
    Returns paginated list of cases with sorting by creation date
    """
    try:
        cases_client = boto3.client(
            'connectcases',
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            aws_session_token=credentials['session_token'],
            region_name=credentials['region']
        )
        
        # Get parameters from request
        next_token = request.args.get('next_token')
        search_term = request.args.get('search', '').strip()
        status = request.args.get('status', '').strip()
        selected_domain_id = request.args.get('domain_id', '').strip()
        
        # Get all available domains
        domains_response = cases_client.list_domains(
            maxResults=10
        )
        domains = domains_response.get('domains', [])
        
        if not domains:
            flash('No case domains found. Please create a domain first.', 'warning')
            return render_template('cases/list_cases.html', cases=[], domains=[])
        
        # Use selected domain or first domain as default
        domain_id = selected_domain_id if selected_domain_id else domains[0]['domainId']
        
        # Prepare search parameters
        params = {
            'domainId': domain_id,
            'maxResults': 20,
            'fields': [
                {'id': 'title'},
                {'id': 'status'},
                {'id': 'priority'},
                {'id': 'created_datetime'},
                {'id': 'last_modified_datetime'}
            ],
            'sorts': [
                {
                    'fieldId': 'created_datetime',
                    'sortOrder': 'Desc'
                }
            ]
        }
        
        if next_token:
            params['nextToken'] = next_token
            
        if search_term:
            params['searchTerm'] = search_term
            
        if status:
            params['filter'] = {
                'field': {
                    'equalTo': {
                        'id': 'status',
                        'value': {
                            'stringValue': status
                        }
                    }
                }
            }
            
        print(f"Search params: {params}")  # Debug print
        response = cases_client.search_cases(**params)
        print(f"Response: {response}")  # Debug print
        
        return render_template('cases/list_cases.html',
                             cases=response.get('cases', []),
                             next_token=response.get('nextToken'),
                             search_term=search_term,
                             status=status,
                             domains=domains,
                             selected_domain_id=domain_id)
                             
    except Exception as e:
        print(f"Error listing cases: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('index'))

def get_domain_fields(cases_client, domain_id):
    """Helper function to get all available fields in a domain"""
    try:
        response = cases_client.list_fields(
            domainId=domain_id,
            maxResults=100
        )
        return response.get('fields', [])
    except Exception as e:
        print(f"Error getting domain fields: {str(e)}")
        return []

@app.route('/cases/<domain_id>/<case_id>')
@require_credentials
def view_case(domain_id, case_id):
    """Display detailed information about a specific case
    Args:
        domain_id: ID of the Cases domain
        case_id: Unique identifier for the case
    Shows:
        - Case fields (title, status, creation date)
        - Audit history of case changes
    """
    try:
        cases_client = boto3.client(
            'connectcases',
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            aws_session_token=credentials['session_token'],
            region_name=credentials['region']
        )
        
        print(f"Attempting to fetch case with domain_id: {domain_id}, case_id: {case_id}")
        
        # Get the main case details with known working fields
        case_response = cases_client.get_case(
            domainId=domain_id,
            caseId=case_id,
            fields=[
                {'id': 'title'},
                {'id': 'status'},
                {'id': 'created_datetime'}
            ]
        )
        print(f"GetCase Response: {case_response}")
        
        # Get case audit events
        audit_events = cases_client.get_case_audit_events(
            domainId=domain_id,
            caseId=case_id
        )
        print(f"Audit Events Response: {audit_events}")
        
        # Structure the case data
        case_data = {
            'caseId': case_id,
            'fields': case_response.get('fields', []),
            'tags': case_response.get('tags', {}),
            'templateId': case_response.get('templateId')
        }
        
        return render_template('cases/view_case.html',
                             case=case_data,
                             events=audit_events.get('auditEvents', []),
                             domain_id=domain_id)
                             
    except cases_client.exceptions.ValidationException as ve:
        print(f"Validation error: {str(ve)}")
        flash(f'Validation error: {str(ve)}', 'error')
        return redirect(url_for('list_cases'))
    except cases_client.exceptions.ResourceNotFoundException:
        print("Case not found")
        flash('Case not found', 'error')
        return redirect(url_for('list_cases'))
    except cases_client.exceptions.AccessDeniedException:
        print("Access denied to case")
        flash('Access denied to case', 'error')
        return redirect(url_for('list_cases'))
    except Exception as e:
        print(f"Error retrieving case details: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('list_cases'))

@app.route('/cases/create', methods=['GET', 'POST'])
@require_credentials
def create_case():
    """Handle case creation
    GET: Display case creation form
    POST: Create new case with submitted data
    Required fields:
        - title
        - description
        - priority (defaults to LOW)
    Status is automatically set to 'open'
    """
    try:
        cases_client = boto3.client(
            'connectcases',
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            aws_session_token=credentials['session_token'],
            region_name=credentials['region']
        )
        
        # Get domains first using correct API format
        domains_response = cases_client.list_domains(
            maxResults=10
        )
        
        if not domains_response.get('domains'):
            flash('No case domains found. Please create a domain first.', 'warning')
            return redirect(url_for('list_cases'))
            
        domain_id = domains_response['domains'][0]['domainId']  # Use first domain
        
        if request.method == 'POST':
            # Create new case with correct parameter names
            case_data = {
                'domainId': domain_id,
                'fields': [
                    {
                        'id': 'title',
                        'value': {
                            'stringValue': request.form['title']
                        }
                    },
                    {
                        'id': 'description',
                        'value': {
                            'stringValue': request.form['description']
                        }
                    },
                    {
                        'id': 'priority',
                        'value': {
                            'stringValue': request.form.get('priority', 'LOW')
                        }
                    },
                    {
                        'id': 'status',
                        'value': {
                            'stringValue': 'open'
                        }
                    }
                ]
            }
            
            response = cases_client.create_case(**case_data)
            flash('Case created successfully!', 'success')
            return redirect(url_for('view_case', domain_id=domain_id, case_id=response['case']['caseId']))
            
        return render_template('cases/create_case.html')
                             
    except Exception as e:
        print(f"Error creating case: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('list_cases'))

@app.template_filter('datetime')
def format_datetime(value):
    """Jinja template filter to format ISO timestamps
    Converts ISO format timestamps to readable datetime strings
    Format: YYYY-MM-DD HH:MM:SS
    """
    try:
        if isinstance(value, str):
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        return value
    except:
        return value

@app.template_filter('nl2br')
def nl2br(value):
    """Jinja template filter to convert newlines to HTML breaks
    Replaces \n with <br> tags for proper HTML display
    """
    if value:
        return value.replace('\n', '<br>')
    return value

if __name__ == '__main__':
    app.run(debug=True) 