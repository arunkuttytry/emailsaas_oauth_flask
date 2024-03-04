from flask import Flask, jsonify, request, redirect, session
from flask_pymongo import PyMongo
import imaplib
import email
from itsdangerous import URLSafeSerializer
from functools import wraps
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from flask_ngrok import run_with_ngrok

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb+srv://arunkutty6148:PuNaFybe10uhShP8@emailservice.val2p26.mongodb.net/emailservice"
mongo = PyMongo(app)
app.config['SECRET_KEY'] = '10184da38316643a89c4aa32152a53a5'

# Error Handling
@app.errorhandler(Exception)
def handle_error(e):
    return jsonify(error=str(e)), 500

# API Key Authentication
def authenticate(api_key):
    # Replace this with your actual API key verification logic
    return api_key == 'eyJhcGlfa2V5IjoieW91cl9hcGlfa2V5In0.rjVzsqbei-zKSfVz6fiCp-aZ3pk'

# Decorator for authentication
def authenticate_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or not authenticate(api_key):
            return jsonify(error="Unauthorized"), 401
        return f(*args, **kwargs)
    return decorated_function

# Decorator for input validation
def validate_input(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        data = request.get_json()
        if not data or 'project_id' not in data or 'uniqid' not in data or 'seeds' not in data:
            return jsonify(error="Invalid input data"), 400
        # You can add more specific input validation checks here
        return f(*args, **kwargs)
    return decorated_function

# Function to fetch all IMAP credentials from the database
def get_all_imap_credentials():
    # Fetch all IMAP credentials from the database
    imap_credentials = mongo.db.imap_credentials.find()
    return imap_credentials

# Function to process emails and update user_reports
def process_emails(project_id, uniqid, seeds):
    try:
        # Get all IMAP credentials from the database
        imap_credentials = get_all_imap_credentials()

        for credentials in imap_credentials:
            email_provider = credentials['email_provider']
            username = credentials['username']
            password = credentials['password']

            # Connect to the IMAP server based on the email provider
            if email_provider == 'gmail':
                mail = imaplib.IMAP4_SSL('imap.gmail.com')
                spam_folder = '[Gmail]/Spam'
            elif email_provider == 'yahoo':
                mail = imaplib.IMAP4_SSL('imap.mail.yahoo.com')
                spam_folder = 'Bulk'  # or 'Junk' depending on the preference
            elif email_provider == 'outlook':
                mail = imaplib.IMAP4_SSL('imap-mail.outlook.com')
                spam_folder = 'Junk'
            elif email_provider == 'zoho':
                mail = imaplib.IMAP4_SSL('imap.zoho.com')
                spam_folder = 'Spam'  # Default spam folder name
            else:
                raise Exception("Unsupported email provider")

            # Login to the IMAP server
            mail.login(username, password)
            mail.select('inbox')
            status, data = mail.search(None, 'ALL')
            mail_ids = data[0].split()

            inbox_emails = []
            spam_emails = []

            for email_id in mail_ids:
                status, data = mail.fetch(email_id, '(RFC822)')
                raw_email = data[0][1]
                msg = email.message_from_bytes(raw_email)

                # Check subject or body for uniqid
                if msg['Subject'] and uniqid in msg['Subject']:
                    # Determine delivery status (inbox or spam)
                    delivery_status = 'inbox' if spam_folder != '[Gmail]/Spam' else 'spam'

                    # Store email ID based on delivery status
                    if delivery_status == 'inbox':
                        inbox_emails.append(msg['From'])
                    else:
                        spam_emails.append(msg['From'])

            # Close the mailbox
            mail.close()
            mail.logout()

            # Update the detailed report in the database
            mongo.db.detailed_reports.insert_one({
                "project_id": project_id,
                "uniqid": uniqid,
                "email_id": credentials['username'],  # From email address
                "status": delivery_status,
                "inbox_emails": inbox_emails,
                "spam_emails": spam_emails
            })

    except Exception as e:
        raise e

# OAuth Configuration
CLIENT_SECRET_FILE = 'client_secret.json'
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
flow = Flow.from_client_secrets_file(CLIENT_SECRET_FILE, scopes=SCOPES, redirect_uri='http://localhost:5000/api/oauth/callback')

# Route for OAuth authorization
@app.route('/api/oauth', methods=['GET'])
def oauth():
    authorization_url, _ = flow.authorization_url(prompt='consent')
    return redirect(authorization_url)

# Route for OAuth callback
@app.route('/api/oauth/callback', methods=['GET'])
def oauth_callback():
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    # Use Gmail API with the obtained credentials
    gmail_service = build('gmail', 'v1', credentials=credentials)
    messages = gmail_service.users().messages().list(userId='me').execute().get('messages', [])
    for message in messages:
        msg = gmail_service.users().messages().get(userId='me', id=message['id']).execute()
        process_email(msg)

    return jsonify({'message': 'OAuth authentication successful'})

# Route for generating bearer token
@app.route('/api/generate_token')
def generate_token():
    serializer = URLSafeSerializer(app.config['SECRET_KEY'])
    token = serializer.dumps({'api_key': 'your_api_key'})
    return jsonify({'token': token})

# Route for processing emails
@app.route('/api/process_emails', methods=['POST'])
@authenticate_user
@validate_input
def trigger_email_processing():
    try:
        data = request.get_json()
        project_id = data['project_id']
        uniqid = data['uniqid']
        seeds = data['seeds']

        process_emails(project_id, uniqid, seeds)

        return jsonify(success=True), 200

    except Exception as e:
        return jsonify(error=str(e)), 500

# Route for adding IMAP credentials
@app.route('/api/add_imap_credentials', methods=['POST'])
@authenticate_user
def add_imap_credentials():
    try:
        data = request.get_json()
        email_provider = data.get('email_provider')
        username = data.get('username')
        password = data.get('password')

        if not email_provider or not username or not password:
            return jsonify(error="Missing required fields"), 400

        if email_provider not in ['gmail', 'yahoo', 'outlook', 'zoho']:
            return jsonify(error="Unsupported email provider"), 400

        # Store IMAP credentials in the database
        mongo.db.imap_credentials.insert_one({
            "email_provider": email_provider,
            "username": username,
            "password": password
        })

        return jsonify(success=True), 200

    except Exception as e:
        return jsonify(error=str(e)), 500

if __name__ == '__main__':
    app.run(debug=True)
