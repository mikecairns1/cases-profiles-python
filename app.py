from flask import Flask, render_template, request, flash, redirect, url_for
import boto3
from botocore.config import Config
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

@app.route('/qic', methods=['GET'])
@require_credentials
def list_qic():
    """List all Q in Connect assistants and knowledge bases
    Requires valid AWS credentials
    Flow:
    1. Get Assistant details
    2. List Knowledge Bases
    3. Get detailed information for each Knowledge Base
    """
    try:
        # Get selected assistant ID from query params
        selected_assistant_id = request.args.get('assistant_id')
        sort = request.args.get('sort', 'name')  # Default sort by name
        order = request.args.get('order', 'asc')  # Default order ascending
        print(f"Selected assistant ID: {selected_assistant_id}")
        print(f"Sort: {sort}, Order: {order}")
        
        # Create QConnect client
        qic_client = boto3.client(
            'qconnect',
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            aws_session_token=credentials['session_token'],
            region_name=credentials['region'],
            config=Config(
                connect_timeout=5,
                retries={'max_attempts': 3},
                region_name=credentials['region']
            )
        )
        
        # Step 1: Get Assistant details if selected
        assistant_details = None
        if selected_assistant_id:
            try:
                print("Attempting to get Assistant details...")
                assistant_response = qic_client.get_assistant(
                    assistantId=selected_assistant_id
                )
                print(f"Assistant response: {json.dumps(assistant_response, default=str)}")
                assistant_details = assistant_response
            except Exception as e:
                print(f"Error getting assistant details: {str(e)}")
                flash(f"Error getting assistant details: {str(e)}", 'error')
        
        # Step 2: List Knowledge Bases
        knowledgebases = []
        try:
            print("\nAttempting to list knowledge bases...")
            next_token = None
            page_count = 0
            
            while True:
                page_count += 1
                print(f"\nFetching page {page_count} of knowledge bases...")
                
                # Prepare parameters for the API call
                params = {
                    'maxResults': 100
                }
                
                if next_token:
                    params['nextToken'] = next_token
                
                print(f"API parameters: {json.dumps(params, default=str)}")
                
                # Make the API call
                response = qic_client.list_knowledge_bases(**params)
                print(f"List knowledge bases response: {json.dumps(response, default=str)}")
                
                # Get knowledge bases from this page
                page_kbs = response.get('knowledgeBaseSummaries', [])
                print(f"Found {len(page_kbs)} knowledge bases on this page")
                
                # Print details of each knowledge base for debugging
                for kb in page_kbs:
                    print(f"\nKnowledge Base Details:")
                    print(f"  Name: {kb.get('name')}")
                    print(f"  ID: {kb.get('knowledgeBaseId')}")
                    print(f"  Type: {kb.get('knowledgeBaseType')}")
                    print(f"  Status: {kb.get('status')}")
                    print(f"  Description: {kb.get('description')}")
                    print(f"  Full object: {json.dumps(kb, default=str)}")
                    
                    # Get detailed information for each knowledge base
                    try:
                        print(f"\nGetting details for knowledge base: {kb.get('name')}")
                        kb_details = qic_client.get_knowledge_base(
                            knowledgeBaseId=kb.get('knowledgeBaseId')
                        )
                        print(f"Knowledge base details: {json.dumps(kb_details, default=str)}")
                        
                        # Get file count for this knowledge base
                        try:
                            # Only attempt to get file count for supported knowledge base types
                            supported_types = ['EXTERNAL', 'CUSTOM']
                            if kb.get('knowledgeBaseType') in supported_types:
                                contents_response = qic_client.list_contents(
                                    knowledgeBaseId=kb.get('knowledgeBaseId'),
                                    maxResults=100  # Get up to 100 files to count
                                )
                                # Count files from contentSummaries
                                file_count = len(contents_response.get('contentSummaries', []))
                                print(f"File count for KB {kb.get('name')}: {file_count}")
                            else:
                                file_count = -1  # Use -1 to indicate unsupported type
                                print(f"Knowledge base type {kb.get('knowledgeBaseType')} does not support content listing")
                        except Exception as count_error:
                            print(f"Error getting file count: {str(count_error)}")
                            file_count = 0
                        
                        # Add detailed information to the knowledge base object
                        kb.update({
                            'details': kb_details,
                            'status': kb_details.get('status'),
                            'type': kb_details.get('knowledgeBaseType'),
                            'description': kb_details.get('description'),
                            'lastModifiedTime': kb_details.get('lastModifiedTime'),
                            'createdTime': kb_details.get('createdTime'),
                            'file_count': file_count
                        })
                    except Exception as kb_error:
                        print(f"Error getting knowledge base details: {str(kb_error)}")
                
                knowledgebases.extend(page_kbs)
                
                # Get the next token for pagination
                next_token = response.get('nextToken')
                print(f"Next token: {next_token}")
                
                if not next_token:
                    print("No more pages to fetch")
                    break
            
            print(f"\nTotal knowledge bases found: {len(knowledgebases)}")
            
            # Sort knowledge bases based on the selected criteria
            if sort == 'files':
                # Handle special case for files (handle -1 values)
                knowledgebases.sort(key=lambda x: (x.get('file_count', 0) == -1, x.get('file_count', 0)), reverse=(order == 'desc'))
            else:
                # For other fields, use direct sorting
                knowledgebases.sort(key=lambda x: x.get(sort, ''), reverse=(order == 'desc'))
            
        except Exception as e:
            print(f"Error listing knowledge bases: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            flash(f"Error listing knowledge bases: {str(e)}", 'error')
        
        # Get all assistants for the selection dropdown
        try:
            print("\nAttempting to list assistants...")
            response = qic_client.list_assistants()
            print(f"List assistants response: {json.dumps(response, default=str)}")
            assistants = response.get('assistantSummaries', [])
            print(f"Found {len(assistants)} assistants")
            for assistant in assistants:
                print(f"Assistant: {assistant.get('name')} (ID: {assistant.get('assistantId')})")
        except Exception as e:
            print(f"Error listing assistants: {str(e)}")
            assistants = []
        
        if not assistants:
            flash('No Q in Connect assistants found. Please create an assistant first.', 'warning')
            return render_template('qic/qic.html', assistants=[], knowledgebases=[])
        
        return render_template('qic/qic.html', 
                             assistants=assistants,
                             selected_assistant_id=selected_assistant_id,
                             assistant_details=assistant_details,
                             knowledgebases=knowledgebases,
                             sort=sort,
                             order=order)
                             
    except Exception as e:
        print(f"Top-level error in list_qic: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
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
            
        print(f"Response: {response}")
        
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

@app.route('/domain/<domain_name>/create_profile', methods=['GET', 'POST'])
@require_credentials
def create_profile(domain_name):
    """Handle profile creation for a specific domain
    GET: Display profile creation form
    POST: Create new profile with submitted data
    
    Basic profile fields include:
    - First name
    - Last name
    - Email address
    - Phone number
    - Account number
    """
    try:
        connect_client = boto3.client(
            'customer-profiles',
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            aws_session_token=credentials['session_token'],
            region_name=credentials['region']
        )
        
        if request.method == 'POST':
            # Create profile with submitted data
            profile_data = {
                'DomainName': domain_name,
                'FirstName': request.form.get('first_name', ''),
                'LastName': request.form.get('last_name', ''),
                'EmailAddress': request.form.get('email', ''),
                'PhoneNumber': request.form.get('phone', ''),
                'AccountNumber': request.form.get('account_number', '')
            }
            
            # Remove empty fields
            profile_data = {k: v for k, v in profile_data.items() if v}
            
            response = connect_client.create_profile(**profile_data)
            flash('Profile created successfully!', 'success')
            return redirect(url_for('profile_details', 
                                   domain_name=domain_name, 
                                   profile_id=response['ProfileId']))
        
        return render_template('create_profile.html', domain_name=domain_name)
        
    except Exception as e:
        print(f"Error creating profile: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('list_domain_profiles', domain_name=domain_name))

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
        
        # Validate the inputs to avoid errors
        if not domain_id or not case_id:
            print("Missing domain_id or case_id")
            flash('Missing required information to view the case.', 'error')
            return redirect(url_for('list_cases'))
            
        try:
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
        except KeyError as ke:
            print(f"KeyError when processing case data: {str(ke)}")
            flash(f'Error processing case data: {str(ke)}', 'error')
            return redirect(url_for('list_cases'))
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
    return handle_case_creation()

def handle_case_creation():
    """Handle case creation process
    
    Step 1: Select a Case Domain
    Step 2: Search and select a Customer Profile
    Step 3: Select a Case Template and fill out case fields
    """
    # Import needed modules
    import json
    
    # Get credentials from session
    credentials = get_stored_credentials()
    if not credentials:
        flash('Please log in first.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Create boto3 client for Cases API
        cases_client = boto3.client(
            'connectcases',
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            aws_session_token=credentials['session_token'],
            region_name=credentials['region']
        )
        
        # Create boto3 client for Customer Profiles API
        profiles_client = boto3.client(
            'customer-profiles',
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            aws_session_token=credentials['session_token'],
            region_name=credentials['region']
        )
        
        # Get all available domains
        domains_response = cases_client.list_domains(
            maxResults=10
        )
        domains = domains_response.get('domains', [])
        
        if not domains:
            flash('No case domains found. Please create a domain first.', 'warning')
            return render_template('cases/list_cases.html', cases=[], domains=[])
        
        # Get the current step from query parameters or default to step 1
        step = request.args.get('step', '1')
        
        # Get domain_id from URL parameters (if provided)
        domain_id = request.args.get('domain_id', '')
        
        # Step 1: Select a Domain
        if step == '1':
            # Handle form submission
            if request.method == 'POST':
                form_domain_id = request.form.get('domain_id')
                if form_domain_id:
                    print(f"Selected domain in step 1: {form_domain_id}")
                    return redirect(f"/cases/create?step=2&domain_id={form_domain_id}")
                else:
                    flash('Please select a domain.', 'error')
            
            # Print available domains for debugging
            print(f"Available domains in step 1: {[(d['domainId'], d['name']) for d in domains]}")
            print(f"Selected domain_id (from URL): {domain_id}")
            
            return render_template('cases/create_case_step1.html', domains=domains)
        
        # Step 2: Search and Select a Customer Profile
        elif step == '2':
            # Validate domain_id
            if not domain_id:
                flash('Domain ID is required. Please select a domain first.', 'error')
                return redirect(url_for('create_case', step='1'))
            
            print(f"Domain ID in step 2: {domain_id}")
            print(f"All request.args: {request.args}")
            
            # Get profile domain from Customer Profiles service
            profile_domains_response = profiles_client.list_domains()
            if not profile_domains_response.get('Items'):
                flash('No profile domains found. Please create a profile domain first.', 'error')
                return redirect(url_for('list_cases'))
            
            # Get all available profile domains
            available_profile_domains = profile_domains_response.get('Items', [])
            
            # Initialize variables with default values
            case_domain_name = "Unknown Domain"
            profile_domain_name = available_profile_domains[0]['DomainName'] if available_profile_domains else "default"
            
            # Get the profile domain from query parameters or select the best match
            selected_profile_domain = request.args.get('profile_domain_name')
            
            # If no profile domain is explicitly selected, find the best match
            if not selected_profile_domain:
                # Try to find a better matching profile domain based on the case domain name
                try:
                    case_domain_details = next((d for d in domains if d['domainId'] == domain_id), None)
                    if case_domain_details:
                        case_domain_name = case_domain_details.get('name', 'Unknown Domain')
                        
                        # Try exact match first (case insensitive)
                        case_domain_name_lower = case_domain_name.lower()
                        found_exact_match = False
                        
                        for domain in available_profile_domains:
                            domain_name = domain['DomainName'].lower()
                            # Check for exact match (removing common prefixes/suffixes)
                            if (case_domain_name_lower == domain_name or
                                case_domain_name_lower in domain_name or
                                domain_name in case_domain_name_lower):
                                profile_domain_name = domain['DomainName']
                                print(f"Found exact matching profile domain: {profile_domain_name}")
                                found_exact_match = True
                                break
                                
                        # If no exact match, try partial match
                        if not found_exact_match:
                            # Try to find a domain with any part of the case domain name
                            for domain in available_profile_domains:
                                # More aggressive matching - find any overlap in the names
                                if any(part in domain['DomainName'].lower() for part in case_domain_name_lower.split('-')):
                                    profile_domain_name = domain['DomainName']
                                    print(f"Found partial matching profile domain: {profile_domain_name}")
                                    break
                        
                        print(f"Selected case domain: {case_domain_name} ({domain_id})")
                        print(f"Selected profile domain: {profile_domain_name}")
                    else:
                        print(f"Unable to find details for domain ID: {domain_id}")
                except Exception as e:
                    print(f"Error getting case domain details: {str(e)}")
                    case_domain_name = "Unknown Domain"
            else:
                # Use the explicitly selected profile domain
                profile_domain_name = selected_profile_domain
                print(f"Using explicitly selected profile domain: {profile_domain_name}")
            
            # Define fields to search by
            available_fields = [
                {'key': '_phone', 'display': 'Phone Number'},
                {'key': '_email', 'display': 'Email Address'},
                {'key': '_profileId', 'display': 'Profile ID'},
                {'key': '_fullName', 'display': 'Full Name'},
                {'key': '_account', 'display': 'Account Number'}
            ]
            
            # Get search parameters
            search_field = request.args.get('search_field', '_phone')
            search_term = request.args.get('search', '')
            profiles = []
            
            # Search for profiles if a search term is provided
            if search_term:
                try:
                    # Use the correct key name based on the selected field
                    key_name = search_field
                    
                    # For phone numbers, standardize format
                    if search_field == '_phone' and search_term:
                        # Remove non-digit characters for phone search
                        search_term = ''.join(c for c in search_term if c.isdigit())
                    
                    search_params = {
                        'DomainName': profile_domain_name,
                        'MaxResults': 20,
                        'KeyName': key_name,
                        'Values': [search_term]
                    }
                    
                    # Debug the search parameters
                    print(f"Profile search params: {search_params}")
                    
                    # Try with both search_profiles and a wildcard approach if needed
                    search_response = profiles_client.search_profiles(**search_params)
                    profiles = search_response.get('Items', [])
                    
                    # If no results found, try with a wildcard approach (like in list_domain_profiles)
                    if not profiles and search_field in ['_fullName', '_phone', '_email', '_account']:
                        # Try a more lenient search with a wildcard
                        print(f"No results found with exact match, trying wildcard search")
                        search_params['Values'] = ['*' + search_term + '*']
                        try:
                            wildcard_response = profiles_client.search_profiles(**search_params)
                            profiles = wildcard_response.get('Items', [])
                        except Exception as wild_e:
                            print(f"Wildcard search failed: {str(wild_e)}")
                    
                    print(f"Search found {len(profiles)} profiles")
                except Exception as e:
                    print(f"Error searching profiles: {str(e)}")
                    flash(f"Error searching profiles: {str(e)}", 'error')
            
            # If POST, check if a profile was selected
            if request.method == 'POST':
                profile_id = request.form.get('profile_id')
                post_domain_id = request.form.get('domain_id', domain_id)
                
                if profile_id:
                    try:
                        # Get the selected profile
                        print(f"Attempting to get profile with ID: {profile_id} from domain: {profile_domain_name}")
                        
                        # Try using search_profiles first as it's more forgiving
                        search_response = profiles_client.search_profiles(
                            DomainName=profile_domain_name,
                            KeyName='_profileId',
                            Values=[profile_id],
                            MaxResults=1
                        )
                        
                        selected_profiles = search_response.get('Items', [])
                        
                        # If search didn't find anything, try direct get_profile as fallback
                        if not selected_profiles:
                            try:
                                profile_response = profiles_client.get_profile(
                                    ProfileId=profile_id,
                                    DomainName=profile_domain_name
                                )
                                selected_profiles = [profile_response]
                            except Exception as direct_err:
                                print(f"Direct get_profile failed: {str(direct_err)}")
                                # No profiles found with either method
                                flash(f"Profile not found with ID {profile_id} in domain {profile_domain_name}. Please try another search.", 'error')
                                return redirect(url_for('create_case', step='2', domain_id=domain_id))
                        
                        if selected_profiles:
                            selected_profile = selected_profiles[0]
                            # Store profile_data as a query parameter (JSON encoded)
                            profile_data_with_domain = {
                                'id': selected_profile.get('ProfileId'),
                                'name': f"{selected_profile.get('FirstName', '')} {selected_profile.get('LastName', '')}".strip(),
                                'account': selected_profile.get('AccountNumber', selected_profile.get('ProfileId')),
                                'domain_name': profile_domain_name  # Include the profile domain name
                            }
                            profile_json = json.dumps(profile_data_with_domain)
                            
                            # Use the form's domain_id or fallback to the URL parameter
                            print(f"Redirecting to step 3 with domain_id: {post_domain_id}")
                            # Use direct string construction instead of url_for to avoid URL encoding issues
                            step3_url = f"/cases/create?step=3&domain_id={post_domain_id}&profile_data={profile_json}"
                            return redirect(step3_url)
                        else:
                            flash('Profile not found. Please try another search.', 'error')
                            return redirect(url_for('create_case', step='2', domain_id=domain_id))
                    except Exception as e:
                        print(f"Error retrieving selected profile: {str(e)}")
                        flash(f"Error retrieving profile: {str(e)}", 'error')
                        return redirect(url_for('create_case', step='2', domain_id=domain_id))
            
            # Render the search/select profile page
            return render_template('cases/create_case_step2.html',
                                domain_id=domain_id,
                                case_domain_name=case_domain_name,
                                profile_domain_name=profile_domain_name,
                                available_profile_domains=available_profile_domains,
                                available_fields=available_fields,
                                search_field=search_field,
                                search_term=search_term,
                                profiles=profiles)
        
        # Step 3: Select template and fill out case details
        elif step == '3':
            print(f"Starting step 3 with domain_id: {domain_id}")
            print(f"All request.args in step 3: {request.args}")
            
            # Get profile data from query parameters
            profile_data_str = request.args.get('profile_data', '{}')
            print(f"Raw profile_data_str: {profile_data_str}")
            
            profile_data = {}
            try:
                profile_data = json.loads(profile_data_str)
                print(f"Successfully parsed profile_data: {profile_data}")
            except Exception as e:
                print(f"Error parsing profile data: {str(e)}")
                print(f"Failed to parse: '{profile_data_str}'")
                flash('Error retrieving profile details. Please select a profile again.', 'error')
                return redirect(url_for('create_case', step='2', domain_id=domain_id))
            
            if not profile_data or 'id' not in profile_data:
                flash('Please select a profile first.', 'error')
                return redirect(url_for('create_case', step='2', domain_id=domain_id))
            
            # Extract profile domain name from profile_data
            profile_domain_name = profile_data.get('domain_name')
            if not profile_domain_name:
                # If not provided, get the first available profile domain
                try:
                    profile_domains_response = profiles_client.list_domains()
                    if profile_domains_response.get('Items'):
                        profile_domain_name = profile_domains_response['Items'][0]['DomainName']
                    else:
                        profile_domain_name = "unknown-domain"
                except Exception as e:
                    print(f"Error getting profile domains: {str(e)}")
                    profile_domain_name = "unknown-domain"
            
            print(f"Using profile domain name: {profile_domain_name}")
            
            # Get templates for the selected domain
            templates_response = cases_client.list_templates(
                domainId=domain_id,
                maxResults=10
            )
            templates = templates_response.get('templates', [])
            
            # Get template_id from query parameters or form submission
            form_template_id = request.form.get('template_id')
            template_id_from_url = request.args.get('template_id')
            selected_template_id = form_template_id or template_id_from_url or (templates[0]['templateId'] if templates else None)
            
            # Get template fields if a template is selected
            template_fields = []
            fields_response = None
            if selected_template_id:
                try:
                    # First get the template to find the layout ID
                    fields_response = cases_client.get_template(
                        domainId=domain_id,
                        templateId=selected_template_id
                    )
                    print(f"Template response: {json.dumps(fields_response, default=str)}")
                    
                    # Check if there's a layout configuration
                    if 'layoutConfiguration' in fields_response and 'defaultLayout' in fields_response['layoutConfiguration']:
                        layout_id = fields_response['layoutConfiguration']['defaultLayout']
                        print(f"Found layout ID: {layout_id}")
                        
                        # Get the layout which should contain the fields
                        try:
                            layout_response = cases_client.get_layout(
                                domainId=domain_id,
                                layoutId=layout_id
                            )
                            print(f"Layout response: {json.dumps(layout_response, default=str)}")
                            
                            # Define system-managed fields that should not be editable
                            system_managed_fields = ['reference_number', 'created_datetime', 'last_updated_datetime']
                            
                            # Extract fields based on the actual nested structure in the response
                            if 'content' in layout_response:
                                # Collect fields from all sections in both topPanel and moreInfo
                                content = layout_response['content']
                                
                                # Process fields in the basic.topPanel section
                                if 'basic' in content and 'topPanel' in content['basic'] and 'sections' in content['basic']['topPanel']:
                                    for section in content['basic']['topPanel']['sections']:
                                        if 'fieldGroup' in section and 'fields' in section['fieldGroup']:
                                            for field_id in section['fieldGroup']['fields']:
                                                # Convert simple field IDs to field objects
                                                if isinstance(field_id, dict) and 'id' in field_id:
                                                    field_id_value = field_id['id']
                                                    # Skip system-managed fields
                                                    if field_id_value not in system_managed_fields:
                                                        template_fields.append({
                                                            'id': field_id_value,
                                                            'name': field_id.get('name', field_id_value),
                                                            'description': field_id.get('description', ''),
                                                            'required': field_id.get('required', False)
                                                        })
                                
                                # Process fields in the basic.moreInfo section
                                if 'basic' in content and 'moreInfo' in content['basic'] and 'sections' in content['basic']['moreInfo']:
                                    for section in content['basic']['moreInfo']['sections']:
                                        if 'fieldGroup' in section and 'fields' in section['fieldGroup']:
                                            for field_id in section['fieldGroup']['fields']:
                                                # Convert simple field IDs to field objects
                                                if isinstance(field_id, dict) and 'id' in field_id:
                                                    field_id_value = field_id['id']
                                                    # Skip system-managed fields
                                                    if field_id_value not in system_managed_fields:
                                                        template_fields.append({
                                                            'id': field_id_value,
                                                            'name': field_id.get('name', field_id_value),
                                                            'description': field_id.get('description', ''),
                                                            'required': field_id.get('required', False)
                                                        })
                                                else:
                                                    # For string field IDs, check if it's not a system-managed field
                                                    if field_id not in system_managed_fields:
                                                        template_fields.append({
                                                            'id': field_id,
                                                            'name': field_id,
                                                            'required': False
                                                        })
                        except Exception as layout_error:
                            print(f"Error getting layout: {str(layout_error)}")
                    else:
                        print("No layoutConfiguration or defaultLayout found in template")
                    
                    # Use fields from the template response if layout doesn't have any
                    if not template_fields and 'requiredFields' in fields_response:
                        print(f"Using requiredFields from template: {fields_response['requiredFields']}")
                        template_fields = fields_response['requiredFields']
                    
                    print(f"Final template_fields: {template_fields}")
                except Exception as e:
                    print(f"Error getting template fields: {str(e)}")
                    flash(f'Error retrieving template fields: {str(e)}', 'error')
            
            # Process form submission for case creation
            if request.method == 'POST':
                form_template_id = request.form.get('template_id')
                
                if not form_template_id:
                    flash('Please select a template.', 'error')
                    return redirect(url_for('create_case', step='3', domain_id=domain_id, profile_data=profile_data_str))
                
                # Log form data for debugging
                print(f"Form data: {request.form}")
                
                # Define system-managed fields that should not be editable
                system_managed_fields = ['reference_number', 'created_datetime', 'last_updated_datetime']
                
                # Build case fields from form data
                fields = []
                for field in template_fields:
                    field_id = field.get('id')
                    # Skip system-managed fields
                    if field_id and field_id not in system_managed_fields and field_id in request.form:
                        field_value = request.form.get(field_id, '')
                        fields.append({
                            'id': field_id,
                            'value': {
                                'stringValue': field_value
                            }
                        })
                
                print(f"Fields from form: {fields}")
                
                # Ensure required fields are included
                required_fields = ['title']
                for field_id in required_fields:
                    if not any(field['id'] == field_id for field in fields):
                        if field_id in request.form and request.form[field_id]:
                            # Field exists in form but wasn't added to fields
                            fields.append({
                                'id': field_id,
                                'value': {
                                    'stringValue': request.form[field_id]
                                }
                            })
                        else:
                            # Field doesn't exist in form or is empty
                            flash(f"The field '{field_id}' is required. Please fill it in.", 'error')
                            return render_template('cases/create_case_step3.html',
                                            domain_id=domain_id, 
                                            profile_data=profile_data,
                                            templates=templates,
                                            selected_template_id=selected_template_id,
                                            template_fields=template_fields)
                
                # Add profile association as a comment field
                profile_association_found = any(field['id'] == 'profile_association' for field in fields)
                if not profile_association_found:
                    # Check if this field exists in the template's available fields
                    if any(template_field.get('id') == 'profile_association' for template_field in template_fields):
                        fields.append({
                            'id': 'profile_association',
                            'value': {
                                'stringValue': f"Profile ID: {profile_data['id']} - Name: {profile_data['name']}"
                            }
                        })
                
                # Ensure status is set
                status_found = any(field['id'] == 'status' for field in fields)
                if not status_found:
                    fields.append({
                        'id': 'status',
                        'value': {
                            'stringValue': 'open'
                        }
                    })
                
                # Validate all fields against the template's available fields
                valid_field_ids = [field.get('id') for field in template_fields]
                
                # For every required field, add a field even if the user didn't submit it
                if fields_response and 'requiredFields' in fields_response:
                    for required_field in fields_response.get('requiredFields', []):
                        if required_field.get('id') and required_field.get('id') not in [f.get('id') for f in fields]:
                            # Skip system-managed fields
                            if required_field.get('id') not in system_managed_fields:
                                print(f"Adding required field: {required_field.get('id')}")
                                fields.append({
                                    'id': required_field.get('id'),
                                    'value': {
                                        'stringValue': ''
                                    }
                                })
                
                # Add title field if it's required by the API but wasn't in the template fields
                if not any(field['id'] == 'title' for field in fields) and request.form.get('title'):
                    print("Adding title field from form data")
                    fields.append({
                        'id': 'title',
                        'value': {
                            'stringValue': request.form.get('title')
                        }
                    })
                
                # Make sure we exclude system-managed fields from the final list
                valid_fields = []
                for field in fields:
                    # Skip fields with empty values
                    if not field.get('value', {}).get('stringValue', '').strip():
                        print(f"Skipping empty field: {field['id']}")
                        continue
                    
                    # Skip system-managed fields
                    if field['id'] in system_managed_fields:
                        print(f"Skipping system-managed field: {field['id']}")
                        continue
                        
                    # Validate customer_id ARN if it exists
                    if field['id'] == 'customer_id':
                        arn_value = field['value'].get('stringValue', '')
                        if '000000000000' in arn_value or not arn_value.strip():
                            print(f"Skipping invalid customer_id ARN: {arn_value}")
                            continue
                    
                    # Include valid fields
                    if field['id'] in valid_field_ids or field['id'] == 'title' or field['id'] == 'customer_id':
                        valid_fields.append(field)
                
                # Create case data dictionary with validated fields
                case_data = {
                    'domainId': domain_id,
                    'templateId': form_template_id,
                    'fields': valid_fields
                }
                
                # Check if we already have a customer_id field
                has_customer_id = any(field['id'] == 'customer_id' for field in valid_fields)
                
                # Add a proper customer_id ARN if it doesn't exist in fields
                if not has_customer_id:
                    try:
                        # Get AWS account information
                        sts_client = boto3.client(
                            'sts',
                            aws_access_key_id=credentials['access_key'],
                            aws_secret_access_key=credentials['secret_key'],
                            aws_session_token=credentials['session_token'],
                            region_name=credentials['region']
                        )
                        
                        # Create the ARN format
                        aws_account_id = sts_client.get_caller_identity().get('Account')
                        aws_region = credentials['region']
                        
                        # Make sure we have the necessary profile data
                        if profile_domain_name and profile_data.get('id'):
                            # Ensure the profile domain and ID are properly formatted
                            profile_domain = profile_domain_name.strip()
                            profile_id = profile_data['id'].strip()
                            
                            if profile_domain and profile_id:
                                customer_arn = f"arn:aws:profile:{aws_region}:{aws_account_id}:domains/{profile_domain}/profiles/{profile_id}"
                                
                                print(f"Adding customer_id ARN: {customer_arn}")
                                case_data['fields'].append({
                                    'id': 'customer_id',
                                    'value': {
                                        'stringValue': customer_arn
                                    }
                                })
                            else:
                                print(f"Warning: Empty profile domain ({profile_domain}) or ID ({profile_id})")
                        else:
                            print(f"Warning: Missing profile data for ARN. domain: {profile_domain_name}, id: {profile_data.get('id')}")
                    except Exception as e:
                        print(f"Error creating customer ARN: {str(e)}")
                        print("Skipping customer_id field due to error")
                
                # Debugging information
                print(f"Final case data: {json.dumps(case_data, default=str)}")
                
                # Create the case
                try:
                    response = cases_client.create_case(**case_data)
                    print(f"Create case response: {json.dumps(response, default=str)}")
                    
                    # Validate the response contains the expected data
                    # The API returns caseId at the top level, not in a 'case' object
                    if response and 'caseId' in response:
                        case_id = response['caseId']
                        flash('Case created successfully!', 'success')
                        # Redirect to the view case page
                        return redirect(url_for('view_case', domain_id=domain_id, case_id=case_id))
                    else:
                        # Missing expected data in response
                        print(f"Unexpected response format: {response}")
                        flash('Case was created but the response was in an unexpected format.', 'warning')
                        return redirect(url_for('list_cases'))
                except Exception as e:
                    print(f"Error creating case: {str(e)}")
                    flash(f'Error creating case: {str(e)}', 'error')
                    return redirect(url_for('create_case', step='3', domain_id=domain_id, profile_data=request.args.get('profile_data'), template_id=selected_template_id))
            
            # Render the template for step 3 if it's not a POST request or if we didn't return earlier
            return render_template('cases/create_case_step3.html',
                                domain_id=domain_id, 
                                profile_data=profile_data,
                                templates=templates,
                                selected_template_id=selected_template_id,
                                template_fields=template_fields)
        
        # Default case - if step is not 1, 2, or 3, redirect to step 1
        else:
            flash('Invalid step. Please start from the beginning.', 'error')
            return redirect(url_for('create_case', step='1'))
                                
    except Exception as e:
        print(f"Error in create_case: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('list_cases'))

@app.route('/qic/knowledge-base/<knowledge_base_id>')
@require_credentials
def view_knowledge_base(knowledge_base_id):
    """Display detailed information about a specific knowledge base"""
    kb_data = fetch_knowledge_base_data(knowledge_base_id)
    return render_template('qic/view_knowledge_base.html', knowledge_base=kb_data)

def fetch_knowledge_base_data(knowledge_base_id):
    """Fetch and process knowledge base data"""
    qic_client = create_qconnect_client()
    kb_response = get_knowledge_base_details(qic_client, knowledge_base_id)
    assistants = get_assistants(qic_client)
    files, content_types, pagination = get_knowledge_base_contents(qic_client, knowledge_base_id)
    
    return structure_knowledge_base_data(knowledge_base_id, kb_response, assistants, files, content_types, pagination)

def create_qconnect_client():
    """Create and return a QConnect client"""
    return boto3.client(
        'qconnect',
        aws_access_key_id=credentials['access_key'],
        aws_secret_access_key=credentials['secret_key'],
        aws_session_token=credentials['session_token'],
        region_name=credentials['region'],
        config=Config(
            connect_timeout=5,
            retries={'max_attempts': 3},
            region_name=credentials['region']
        )
    )

def get_knowledge_base_details(qic_client, knowledge_base_id):
    """Get knowledge base details"""
    try:
        return qic_client.get_knowledge_base(knowledgeBaseId=knowledge_base_id)
    except Exception as e:
        print(f"Error getting knowledge base details: {str(e)}")
        flash(f'Error retrieving knowledge base details: {str(e)}', 'error')
        return redirect(url_for('list_qic'))

def get_assistants(qic_client):
    """Get all assistants"""
    assistants_response = qic_client.list_assistants()
    return assistants_response.get('assistantSummaries', [])

def get_knowledge_base_contents(qic_client, knowledge_base_id):
    """Get list of files in the knowledge base with filtering"""
    content_type = request.args.get('content_type', '')
    status = request.args.get('status', '')
    search_term = request.args.get('search', '')
    next_token = request.args.get('next_token')
    max_results = int(request.args.get('max_results', 20))
    
    files = []
    total_files = 0
    content_types = set()
    
    try:
        while True:
            params = build_content_params(knowledge_base_id, content_type, status, search_term, next_token, max_results)
            contents_response = qic_client.list_contents(**params)
            
            page_files = contents_response.get('contentSummaries', [])
            files.extend(page_files)
            total_files += len(page_files)
            
            for file in page_files:
                if file.get('type'):
                    content_types.add(file['type'])
            
            next_token = contents_response.get('nextToken')
            if not next_token or len(files) >= max_results:
                break
        
    except Exception as content_error:
        print(f"Error listing knowledge base contents: {str(content_error)}")
        flash(f"Error listing knowledge base contents: {str(content_error)}", 'error')
        files = []
        next_token = None
    
    pagination = {
        'next_token': next_token,
        'max_results': max_results,
        'total_files': total_files
    }
    
    return files, sorted(list(content_types)), pagination

def build_content_params(knowledge_base_id, content_type, status, search_term, next_token, max_results):
    """Build parameters for listing contents"""
    params = {
        'knowledgeBaseId': knowledge_base_id,
        'maxResults': max_results
    }
    if content_type:
        params['contentType'] = content_type
    if status:
        params['status'] = status
    if search_term:
        params['searchTerm'] = search_term
    if next_token:
        params['nextToken'] = next_token
    return params

def structure_knowledge_base_data(knowledge_base_id, kb_response, assistants, files, content_types, pagination):
    """Structure the knowledge base data"""
    return {
        'id': knowledge_base_id,
        'name': kb_response.get('name'),
        'type': kb_response.get('knowledgeBaseType'),
        'status': kb_response.get('status'),
        'description': kb_response.get('description'),
        'lastModifiedTime': kb_response.get('lastModifiedTime'),
        'createdTime': kb_response.get('createdTime'),
        'content': kb_response.get('content'),
        'assistants': assistants,
        'files': files,
        'content_types': content_types,
        'filters': {
            'content_type': request.args.get('content_type', ''),
            'status': request.args.get('status', ''),
            'search': request.args.get('search', '')
        },
        'pagination': pagination
    }

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