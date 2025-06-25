"""
SQLite to MongoDB Migration Script for ProtectIT

This script reads data from the SQLite database and transfers it to MongoDB.
Run it once to migrate existing data when switching from SQLite to MongoDB.
"""

import sqlite3
import sys
import os
from datetime import datetime
from pymongo import MongoClient

# MongoDB Configuration
MONGO_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017')
MONGO_DB = os.environ.get('MONGODB_DB', 'protectit')

def migrate_sqlite_to_mongo():
    """
    Migrate all data from SQLite to MongoDB
    Returns the number of records migrated
    """
    try:
        # Check if the SQLite file exists
        if not os.path.exists('protectit.db'):
            print("SQLite database file not found. Nothing to migrate.")
            return 0
        
        # Connect to SQLite
        sqlite_conn = sqlite3.connect('protectit.db')
        sqlite_conn.row_factory = sqlite3.Row  # This enables column access by name
        cursor = sqlite_conn.cursor()
        
        # Connect to MongoDB
        mongo_client = MongoClient(MONGO_URI)
        db = mongo_client[MONGO_DB]
        
        # Collections
        scan_results_collection = db.scan_results
        system_info_collection = db.system_info
        scans_collection = db.scans
        
        # Migrate scan results
        cursor.execute("SELECT * FROM scan_results")
        scan_results = [dict(row) for row in cursor.fetchall()]
        
        if scan_results:
            # Remove SQLite's id field
            for result in scan_results:
                if 'id' in result:
                    del result['id']
            
            scan_results_collection.insert_many(scan_results)
            print(f"Migrated {len(scan_results)} scan results")
        
        # Migrate system info
        cursor.execute("SELECT * FROM system_info")
        system_infos = [dict(row) for row in cursor.fetchall()]
        
        if system_infos:
            # Remove SQLite's id field
            for info in system_infos:
                if 'id' in info:
                    del info['id']
            
            system_info_collection.insert_many(system_infos)
            print(f"Migrated {len(system_infos)} system info records")
        
        # Migrate scans
        cursor.execute("SELECT * FROM scans")
        scans = [dict(row) for row in cursor.fetchall()]
        
        if scans:
            # Remove SQLite's id field
            for scan in scans:
                if 'id' in scan:
                    del scan['id']
            
            scans_collection.insert_many(scans)
            print(f"Migrated {len(scans)} scan records")
        
        total_records = len(scan_results) + len(system_infos) + len(scans)
        print(f"Total records migrated: {total_records}")
        
        # Close connections
        sqlite_conn.close()
        mongo_client.close()
        
        return total_records
        
    except Exception as e:
        print(f"Error during migration: {str(e)}")
        return -1

if __name__ == "__main__":
    print("Starting SQLite to MongoDB migration...")
    record_count = migrate_sqlite_to_mongo()
    
    if record_count > 0:
        print("Migration completed successfully!")
        print(f"Total records migrated: {record_count}")
    elif record_count == 0:
        print("No records found to migrate.")
    else:
        print("Migration failed!")
        sys.exit(1)
