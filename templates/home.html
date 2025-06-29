#!/usr/bin/env python3
"""
Database initialization script for Watch & Earn Flask App
Run this once to create all database tables.

Usage:
    python init_db.py
"""

from app import app, db
from app import User, WithdrawalRequest, Video  # Import all models

def init_database():
    """Create all database tables"""
    try:
        with app.app_context():
            # Create all tables
            db.create_all()
            print("✅ Database tables created successfully!")
            
            # Verify tables were created
            tables = db.engine.table_names()
            print(f"📋 Created tables: {', '.join(tables)}")
            
            # Check if we have any existing users
            user_count = User.query.count()
            print(f"👥 Current user count: {user_count}")
            
    except Exception as e:
        print(f"❌ Error creating database: {str(e)}")
        return False
    
    return True

if __name__ == '__main__':
    print("🚀 Initializing Watch & Earn Database...")
    success = init_database()
    
    if success:
        print("🎉 Database initialization completed!")
    else:
        print("💥 Database initialization failed!")
        exit(1)
