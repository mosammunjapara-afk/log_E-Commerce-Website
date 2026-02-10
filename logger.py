import sqlite3
import logging
from datetime import datetime
from functools import wraps
from flask import request, session
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ecommerce.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('ECommerceLogger')

class ActivityLogger:
    """Comprehensive logging system for the e-commerce application"""
    
    def __init__(self, db_path='ecommerce.db'):
        self.db_path = db_path
        self.init_logs_table()
    
    def init_logs_table(self):
        """Initialize the logs table in the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    log_type TEXT NOT NULL,
                    user_id INTEGER,
                    username TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    status TEXT DEFAULT 'info',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("✅ Activity logs table initialized successfully")
        except Exception as e:
            logger.error(f"❌ Error initializing logs table: {e}")
    
    def log_activity(self, log_type, action, details=None, status='info', user_id=None, username=None):
        """
        Log an activity to the database
        
        Args:
            log_type: Type of log (AUTH, ADMIN, USER, PRODUCT, ORDER, ERROR, SECURITY)
            action: Description of the action
            details: Additional details about the action
            status: Status level (info, success, warning, error, critical)
            user_id: ID of the user performing the action
            username: Username of the user
        """
        try:
            # Get request information
            ip_address = request.remote_addr if request else 'N/A'
            user_agent = request.headers.get('User-Agent', 'N/A') if request else 'N/A'
            
            # Get session information if not provided
            if user_id is None and session and 'user_id' in session:
                user_id = session.get('user_id')
            if username is None and session and 'username' in session:
                username = session.get('username')
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO activity_logs 
                (timestamp, log_type, user_id, username, action, details, ip_address, user_agent, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, log_type, user_id, username, action, details, ip_address, user_agent, status))
            
            conn.commit()
            conn.close()
            
            # Also log to file
            log_message = f"[{log_type}] {action}"
            if details:
                log_message += f" - {details}"
            if username:
                log_message += f" (User: {username})"
            
            if status == 'error' or status == 'critical':
                logger.error(log_message)
            elif status == 'warning':
                logger.warning(log_message)
            else:
                logger.info(log_message)
                
        except Exception as e:
            logger.error(f"❌ Error logging activity: {e}")
    
    def get_all_logs(self, limit=500, log_type=None, status=None):
        """
        Retrieve all logs from the database
        
        Args:
            limit: Maximum number of logs to retrieve
            log_type: Filter by log type
            status: Filter by status
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = 'SELECT * FROM activity_logs WHERE 1=1'
            params = []
            
            if log_type:
                query += ' AND log_type = ?'
                params.append(log_type)
            
            if status:
                query += ' AND status = ?'
                params.append(status)
            
            query += ' ORDER BY id DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            logs = [dict(row) for row in cursor.fetchall()]
            
            conn.close()
            return logs
        except Exception as e:
            logger.error(f"❌ Error retrieving logs: {e}")
            return []
    
    def get_logs_by_user(self, user_id, limit=100):
        """Get logs for a specific user"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM activity_logs 
                WHERE user_id = ? 
                ORDER BY id DESC 
                LIMIT ?
            ''', (user_id, limit))
            
            logs = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return logs
        except Exception as e:
            logger.error(f"❌ Error retrieving user logs: {e}")
            return []
    
    def get_logs_by_type(self, log_type, limit=100):
        """Get logs by type"""
        return self.get_all_logs(limit=limit, log_type=log_type)
    
    def clear_old_logs(self, days=30):
        """Delete logs older than specified days"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM activity_logs 
                WHERE created_at < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            logger.info(f"🗑️ Deleted {deleted_count} old log entries")
            return deleted_count
        except Exception as e:
            logger.error(f"❌ Error clearing old logs: {e}")
            return 0
    
    def get_log_statistics(self):
        """Get statistics about logs"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total logs
            cursor.execute('SELECT COUNT(*) as total FROM activity_logs')
            total_logs = cursor.fetchone()[0]
            
            # Logs by type
            cursor.execute('''
                SELECT log_type, COUNT(*) as count 
                FROM activity_logs 
                GROUP BY log_type
            ''')
            logs_by_type = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Logs by status
            cursor.execute('''
                SELECT status, COUNT(*) as count 
                FROM activity_logs 
                GROUP BY status
            ''')
            logs_by_status = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Recent errors
            cursor.execute('''
                SELECT COUNT(*) as count 
                FROM activity_logs 
                WHERE status IN ('error', 'critical') 
                AND created_at > datetime('now', '-1 day')
            ''')
            recent_errors = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_logs': total_logs,
                'logs_by_type': logs_by_type,
                'logs_by_status': logs_by_status,
                'recent_errors': recent_errors
            }
        except Exception as e:
            logger.error(f"❌ Error getting log statistics: {e}")
            return {}


# Global logger instance
activity_logger = ActivityLogger()


# Decorators for automatic logging

def log_auth(action_description):
    """Decorator for authentication-related actions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                activity_logger.log_activity(
                    log_type='AUTH',
                    action=action_description,
                    status='success'
                )
                return result
            except Exception as e:
                activity_logger.log_activity(
                    log_type='AUTH',
                    action=action_description,
                    details=f"Error: {str(e)}",
                    status='error'
                )
                raise
        return wrapper
    return decorator


def log_admin_action(action_description):
    """Decorator for admin actions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                activity_logger.log_activity(
                    log_type='ADMIN',
                    action=action_description,
                    status='success'
                )
                return result
            except Exception as e:
                activity_logger.log_activity(
                    log_type='ADMIN',
                    action=action_description,
                    details=f"Error: {str(e)}\n{traceback.format_exc()}",
                    status='error'
                )
                raise
        return wrapper
    return decorator


def log_user_action(action_description):
    """Decorator for user actions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                activity_logger.log_activity(
                    log_type='USER',
                    action=action_description,
                    status='info'
                )
                return result
            except Exception as e:
                activity_logger.log_activity(
                    log_type='USER',
                    action=action_description,
                    details=f"Error: {str(e)}",
                    status='error'
                )
                raise
        return wrapper
    return decorator


# Specific logging functions for common events

def log_login_attempt(username, success, reason=None):
    """Log a login attempt"""
    if success:
        activity_logger.log_activity(
            log_type='AUTH',
            action=f'Login successful',
            details=f'Username: {username}',
            status='success',
            username=username
        )
    else:
        activity_logger.log_activity(
            log_type='SECURITY',
            action=f'Login failed',
            details=f'Username: {username}, Reason: {reason or "Invalid credentials"}',
            status='warning',
            username=username
        )


def log_logout(username):
    """Log a logout"""
    activity_logger.log_activity(
        log_type='AUTH',
        action='User logged out',
        details=f'Username: {username}',
        status='info',
        username=username
    )


def log_registration(username, email, success, reason=None):
    """Log a registration attempt"""
    if success:
        activity_logger.log_activity(
            log_type='AUTH',
            action='New user registered',
            details=f'Username: {username}, Email: {email}',
            status='success',
            username=username
        )
    else:
        activity_logger.log_activity(
            log_type='AUTH',
            action='Registration failed',
            details=f'Username: {username}, Email: {email}, Reason: {reason}',
            status='warning'
        )


def log_product_action(action, product_id, product_name, details=None):
    """Log product-related actions"""
    activity_logger.log_activity(
        log_type='PRODUCT',
        action=action,
        details=f'Product ID: {product_id}, Name: {product_name}' + (f', {details}' if details else ''),
        status='success'
    )


def log_order_action(action, order_id, details=None):
    """Log order-related actions"""
    activity_logger.log_activity(
        log_type='ORDER',
        action=action,
        details=f'Order ID: {order_id}' + (f', {details}' if details else ''),
        status='success'
    )


def log_admin_order_update(order_id, old_status, new_status, admin_username):
    """Log admin order status update"""
    activity_logger.log_activity(
        log_type='ADMIN',
        action='Order status updated',
        details=f'Order ID: {order_id}, Changed from "{old_status}" to "{new_status}"',
        status='success',
        username=admin_username
    )


def log_cart_action(action, product_name, quantity=None):
    """Log cart-related actions"""
    details = f'Product: {product_name}'
    if quantity:
        details += f', Quantity: {quantity}'
    
    activity_logger.log_activity(
        log_type='USER',
        action=action,
        details=details,
        status='info'
    )


def log_error(error_type, error_message, details=None):
    """Log an error"""
    activity_logger.log_activity(
        log_type='ERROR',
        action=error_type,
        details=f'{error_message}\n{details if details else ""}',
        status='error'
    )


def log_security_event(event_type, details):
    """Log a security event"""
    activity_logger.log_activity(
        log_type='SECURITY',
        action=event_type,
        details=details,
        status='critical'
    )


def log_database_change(table, action, record_id, details=None):
    """Log database changes"""
    activity_logger.log_activity(
        log_type='DATABASE',
        action=f'{action} in {table}',
        details=f'Record ID: {record_id}' + (f', {details}' if details else ''),
        status='info'
    )


def log_payment_action(action, order_id, amount, payment_method, status='info'):
    """Log payment-related actions"""
    activity_logger.log_activity(
        log_type='PAYMENT',
        action=action,
        details=f'Order ID: {order_id}, Amount: ${amount:.2f}, Method: {payment_method}',
        status=status
    )


def log_validation_error(field, value, reason):
    """Log validation errors"""
    activity_logger.log_activity(
        log_type='VALIDATION',
        action='Validation error',
        details=f'Field: {field}, Value: {value}, Reason: {reason}',
        status='warning'
    )


def log_unauthorized_access(attempted_resource, required_role=None):
    """Log unauthorized access attempts"""
    details = f'Attempted to access: {attempted_resource}'
    if required_role:
        details += f', Required role: {required_role}'
    
    activity_logger.log_activity(
        log_type='SECURITY',
        action='Unauthorized access attempt',
        details=details,
        status='warning'
    )


# Initialize logger on import
logger.info("🚀 Activity Logger initialized")