import sqlite3

def add_payment_method_column():
    """Add payment_method column to existing orders table"""
    try:
        # Connect to database
        conn = sqlite3.connect('ecommerce.db')
        cursor = conn.cursor()
        
        # Check if column already exists
        cursor.execute("PRAGMA table_info(orders)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'payment_method' not in columns:
            # Add the payment_method column
            cursor.execute('''
                ALTER TABLE orders 
                ADD COLUMN payment_method TEXT DEFAULT 'Cash on Delivery'
            ''')
            conn.commit()
            print("✅ SUCCESS: payment_method column added to orders table!")
            print("✅ All existing orders now have 'Cash on Delivery' as payment method")
        else:
            print("ℹ️  Column 'payment_method' already exists in orders table")
        
        conn.close()
        print("\n🎉 Database updated successfully!")
        print("You can now run your Flask application without errors.")
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        print("\nIf you see this error, try Option 2 (Reset Database)")

if __name__ == "__main__":
    print("="*60)
    print("DATABASE MIGRATION: Adding payment_method column")
    print("="*60)