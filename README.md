# Amazon Connect Customer Profiles and Cases GUI

This Flask application provides a web interface for interacting with Amazon Connect Customer Profiles and Cases. It allows users to:

*   Securely store and manage AWS credentials.
*   List, search, and view details of Customer Profiles domains and individual profiles.
*   List, view details of, and create Cases.
*   View audit history of Cases.

## !!!!!Very early testing proceed with Caution. This has many bugs!!!!!

## Prerequisites

*   Python 3.7+
*   An AWS account with appropriate permissions to access Amazon Connect Customer Profiles and Cases.
*   pip

## Installation and Setup

1.  **Clone the repository:**

    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Create a virtual environment (recommended):**

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # On Linux/macOS
    .venv\Scripts\activate  # On Windows
    ```

3.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the application:**

    ```bash
    python app.py
    ```

    The application will be accessible at `http://127.0.0.1:5000/`.

5.  **AWS Credentials:** The first time you run the application, you'll be prompted to enter your AWS credentials (access key, secret key, session token, and region). These credentials are encrypted and stored locally in your home directory under `~/.aws-profiles-gui`.  The application uses these credentials to interact with the AWS services.  You can clear the stored credentials by clicking the "Logout" button.

## Application Structure

*   **`app.py`:** The main Flask application file.  This contains all the routes, logic for interacting with AWS, and data handling.
*   **`templates/`:**  Contains the HTML templates used to render the web pages.
    *   `base.html`:  The base template that other templates inherit from.  It defines the common layout and includes navigation.
    *   `index.html`:  The credential input form.
    *   `profiles.html`:  Displays a list of Customer Profiles domains.
    *   `search_results.html`:  Displays search results for Customer Profiles.
    *   `profile_details.html`:  Shows details of a specific Customer Profile.
    *   `domain_details.html`:  Shows details of a specific Customer Profiles domain.
    *   `domain_profiles.html`: Lists profiles within a specific domain, with search functionality.
    *   `create_profile.html`: Form for creating a new customer profile.
    *   `cases/list_cases.html`: Lists Connect Cases with filtering and pagination.
    *   `cases/view_case.html`: Displays details of a specific Case, including audit history.
    *   `cases/create_case.html`: Form for creating a new Case.
    *   `cases/create_case_step1.html`: First step of case creation workflow.
    *   `cases/create_case_step2.html`: Second step of case creation workflow.
    *   `cases/create_case_step3.html`: Final step of case creation workflow.
    *   `qic/qic.html`: Lists Q in Connect assistants and knowledge bases.
    *   `qic/view_knowledge_base.html`: Shows details of a specific knowledge base.
*   **`requirements.txt`:** Lists the Python dependencies for the project.

## Extending to Other Amazon Connect Services

This application is designed to be easily extended to support other Amazon Connect services. Here's a step-by-step guide:

1.  **Identify the Service and API:** Determine which Amazon Connect service you want to integrate (e.g., Amazon Connect Wisdom, Amazon Connect Voice ID, Amazon Connect Tasks, etc.).  Find the corresponding Boto3 client name and API documentation.  For example, for Wisdom, the client is `wisdom` and you'd use the `boto3.client('wisdom')` to interact with it.

2.  **Create New Routes:** Add new routes in `app.py` to handle the interactions with the new service.  Each route should correspond to a specific action (e.g., listing resources, creating a resource, viewing details).  Use the `@require_credentials` decorator to ensure that AWS credentials are set before accessing these routes.

3.  **Implement AWS Interaction:** Within each new route, use the Boto3 client to interact with the chosen service.  Use the `credentials` dictionary (available globally in `app.py`) to provide the necessary AWS credentials to the Boto3 client.  Handle potential errors (e.g., API call failures, insufficient permissions) gracefully using `try...except` blocks and display appropriate messages to the user using `flash()`.

4.  **Create New Templates (if needed):**  Create new HTML templates in the `templates/` directory to display the data retrieved from the new service.  You can reuse existing templates or create new ones as needed.  Use Jinja2 templating to display data dynamically. Consider creating subdirectories within `templates/` to organize templates by service (e.g., `templates/wisdom/`).

5.  **Update Navigation (if needed):** Add links to the new routes in the navigation bar (likely in `templates/base.html`) so users can easily access the new functionality.

6.  **Example: Adding Amazon Connect Wisdom Support**

    *   **Step 1 (Identify Service):**  We'll add support for listing Wisdom assistant. The Boto3 client is `wisdom`.

    *   **Step 2 & 3 (Routes and AWS Interaction):**  Add a new route in `app.py`:

    ```python:app.py
    @app.route('/wisdom/assistants')
    @require_credentials
    def list_wisdom_assistants():
        try:
            wisdom_client = boto3.client(
                'wisdom',
                aws_access_key_id=credentials['access_key'],
                aws_secret_access_key=credentials['secret_key'],
                aws_session_token=credentials['session_token'],
                region_name=credentials['region']
            )
            response = wisdom_client.list_assistants()
            assistants = response['assistantSummaries']
            return render_template('wisdom/list_assistants.html', assistants=assistants)
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('index'))
    ```

    *   **Step 4 (Create Template):** Create `templates/wisdom/list_assistants.html`:

    ```html:templates/wisdom/list_assistants.html
    {% extends "base.html" %}

    {% block content %}
    <h2>Wisdom Assistants</h2>
    <ul>
        {% for assistant in assistants %}
        <li>{{ assistant.name }} (ID: {{ assistant.assistantId }}) - Type: {{ assistant.type }}</li>
        {% endfor %}
    </ul>
    {% endblock %}
    ```
    *   **Step 5 (Update Navigation):** Add to `templates/base.html`:
    ```html:templates/base.html
    <li><a href="{{ url_for('list_wisdom_assistants') }}">Wisdom Assistants</a></li>
    ```

7.  **Error Handling:** Implement robust error handling throughout your code.  Catch specific exceptions (e.g., `botocore.exceptions.ClientError`, `botocore.exceptions.ParamValidationError`) to provide more informative error messages to the user.

8.  **Pagination:** For services that return large numbers of results, implement pagination using the `NextToken` parameter provided by many AWS APIs.  See the `list_domain_profiles` and `list_cases` functions in `app.py` for examples.

9.  **Security:** Always follow best practices for security.  Never hardcode AWS credentials.  Ensure that your application is protected against common web vulnerabilities (e.g., cross-site scripting, SQL injection).

10. **Template Filters:**  Use template filters (like `datetime` and `nl2br` in `app.py`) to format data appropriately for display in your templates.  Create additional filters as needed.

By following these steps, you can extend this application to manage a wide range of Amazon Connect services, creating a centralized interface for your Connect operations. Remember to consult the Boto3 documentation for each service to understand the available API calls and parameters.