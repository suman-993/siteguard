# database.py
# This script initializes the SQLite database and provides
# helper functions for the WAF to interact with it.

import sqlite3
import datetime

DB_NAME = 'siteguard.db'

def init_db():
    """
    Initializes the database and creates tables if they don't exist.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Table for logging all suspicious, blocked events
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS suspicious_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            reason TEXT NOT NULL,
            request_path TEXT
        )
        ''')
        
        # Table for managing currently blocked IPs
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip_address TEXT PRIMARY KEY NOT NULL,
            blocked_until DATETIME NOT NULL,
            reason TEXT NOT NULL
        )
        ''')
        
        conn.commit()
        print(f"Database '{DB_NAME}' initialized successfully.")
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")
    finally:
        if conn:
            conn.close()

def log_suspicious_activity(ip, reason, path):
    """
    Logs a suspicious event to the 'suspicious_logs' table.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now()
        cursor.execute(
            "INSERT INTO suspicious_logs (ip_address, timestamp, reason, request_path) VALUES (?, ?, ?, ?)",
            (ip, timestamp, reason, path)
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error logging suspicious activity: {e}")
    finally:
        if conn:
            conn.close()

def block_ip(ip, reason, minutes):
    """
    Blocks an IP by adding it to the 'blocked_ips' table.
    Also logs the event.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        blocked_until = datetime.datetime.now() + datetime.timedelta(minutes=minutes)
        
        # Use INSERT OR REPLACE to update the block time if already blocked
        cursor.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip_address, blocked_until, reason) VALUES (?, ?, ?)",
            (ip, blocked_until, reason)
        )
        conn.commit()
        print(f"BLOCKED IP: {ip} for {reason}.")
        # Also log this as a suspicious event
        log_suspicious_activity(ip, f"IP BLOCKED: {reason}", "N/A")
    except sqlite3.Error as e:
        print(f"Error blocking IP: {e}")
    finally:
        if conn:
            conn.close()

def is_ip_blocked(ip):
    """
    Checks if an IP is currently in the blocked list and the block is still active.
    """
    is_blocked = False
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT blocked_until FROM blocked_ips WHERE ip_address = ?", (ip,)
        )
        row = cursor.fetchone()
        
        if row:
            blocked_until = datetime.datetime.fromisoformat(row['blocked_until'])
            if blocked_until > datetime.datetime.now():
                is_blocked = True
            else:
                # The block has expired, remove it
                remove_expired_block(ip)
                
    except sqlite3.Error as e:
        print(f"Error checking if IP is blocked: {e}")
    finally:
        if conn:
            conn.close()
    return is_blocked

def remove_expired_block(ip):
    """
    Removes an expired block from the 'blocked_ips' table.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error removing expired block: {e}")
    finally:
        if conn:
            conn.close()

def get_dashboard_data():
    """
    Retrieves stats and logs for the dashboard.
    """
    stats = {
        'total_blocked_events': 0,
        'unique_blocked_ips': 0,
        'attack_types': []
    }
    logs = []
    blocked_ips = []
    
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # 1. Get total blocked events
        cursor.execute("SELECT COUNT(*) as count FROM suspicious_logs WHERE reason LIKE 'IP BLOCKED:%'")
        stats['total_blocked_events'] = cursor.fetchone()['count']
        
        # 2. Get currently blocked IPs
        cursor.execute("SELECT ip_address, blocked_until, reason FROM blocked_ips WHERE blocked_until > ?", (datetime.datetime.now(),))
        blocked_ips = [dict(row) for row in cursor.fetchall()]
        stats['unique_blocked_ips'] = len(blocked_ips)
        
        # 3. Get attack type breakdown
        cursor.execute("SELECT reason, COUNT(*) as count FROM suspicious_logs GROUP BY reason ORDER BY count DESC")
        stats['attack_types'] = [dict(row) for row in cursor.fetchall()]

        # 4. Get recent suspicious logs (last 50)
        cursor.execute("SELECT ip_address, timestamp, reason, request_path FROM suspicious_logs ORDER BY timestamp DESC LIMIT 50")
        logs = [dict(row) for row in cursor.fetchall()]
        
    except sqlite3.Error as e:
        print(f"Error getting dashboard data: {e}")
    finally:
        if conn:
            conn.close()
            
    return {'stats': stats, 'logs': logs, 'blocked_ips': blocked_ips}

if __name__ == '__main__':
    # This allows you to run `python3 database.py` to create the DB
    init_db()