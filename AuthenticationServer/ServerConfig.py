# Server Configuration for the Kerberos-based Authentication Server

# Server IP and Port Configuration
SERVER_IP = '127.0.0.1'
SERVER_PORT = 12345

# Encryption Key Configuration
ENCRYPTION_KEY = 'your-encryption-key'  # This should be a secure key

# Ticket and Authentication Settings
TICKET_VALIDITY_DURATION = 3600  # Validity of tickets in seconds (e.g., 1 hour)
MAX_AUTH_ATTEMPTS = 5  # Max number of authentication attempts
TIME_SYNC_TOLERANCE = 5  # Tolerance in seconds for time synchronization

# Logging and Monitoring
LOG_FILE_PATH = 'path/to/log/file.log'
LOG_LEVEL = 'DEBUG'  # Can be INFO, DEBUG, ERROR, etc.

# Security Settings
SSL_CERT_PATH = 'path/to/ssl/cert'  # If using SSL/TLS
SSL_KEY_PATH = 'path/to/ssl/key'

# Database Configuration (if using a database)
DB_HOST = 'database_host'
DB_PORT = 3306
DB_USERNAME = 'username'
DB_PASSWORD = 'password'
DB_NAME = 'database_name'

# Additional Network Settings
NETWORK_TIMEOUT = 30  # Network timeout in seconds
RATE_LIMIT = 100  # Max number of requests per minute

# Version Information
PROTOCOL_VERSION = '1.0'

# File Paths for Data Storage
CLIENTS_FILE_PATH = 'path/to/clients/data'
TICKETS_FILE_PATH = 'path/to/tickets/data'

# Any additional configurations can be added here