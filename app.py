from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import os

# Import the logging system - CORRECTED IMPORT
from logger import (
    activity_logger,
    log_login_attempt,
    log_logout,
    log_registration,
    log_product_action,
    log_order_action,
    log_admin_order_update,
    log_cart_action,
    log_error,
    log_security_event,
    log_database_change,
    log_payment_action,
    log_validation_error,
    log_unauthorized_access
)

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Database setup
def init_db():
    conn = sqlite3.connect('ecommerce.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  is_admin INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Categories table
    c.execute('''CREATE TABLE IF NOT EXISTS categories
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT UNIQUE NOT NULL,
                  icon TEXT)''')
    
    # Products table
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  description TEXT,
                  price REAL NOT NULL,
                  stock INTEGER DEFAULT 0,
                  category_id INTEGER,
                  image_url TEXT,
                  rating REAL DEFAULT 0,
                  reviews_count INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(category_id) REFERENCES categories(id))''')
    
    # Orders table
    c.execute('''CREATE TABLE IF NOT EXISTS orders
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  total REAL,
                  status TEXT DEFAULT 'pending',
                  shipping_address TEXT,
                  payment_method TEXT DEFAULT 'Cash on Delivery',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    # Order items table
    c.execute('''CREATE TABLE IF NOT EXISTS order_items
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  order_id INTEGER,
                  product_id INTEGER,
                  quantity INTEGER,
                  price REAL,
                  FOREIGN KEY(order_id) REFERENCES orders(id),
                  FOREIGN KEY(product_id) REFERENCES products(id))''')
    
    # Wishlist table
    c.execute('''CREATE TABLE IF NOT EXISTS wishlist
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  product_id INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(user_id) REFERENCES users(id),
                  FOREIGN KEY(product_id) REFERENCES products(id))''')
    
    # Create default admin
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        admin_password = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)",
                 ('admin', 'admin@estore.com', admin_password, 1))
        activity_logger.log_activity('ADMIN', 'Default admin account created', status='success')
    
    # Add categories if none exist
    c.execute("SELECT COUNT(*) FROM categories")
    if c.fetchone()[0] == 0:
        categories = [
            ('Electronics', '💻'),
            ('Fashion', '👕'),
            ('Home & Kitchen', '🏠'),
            ('Sports', '⚽'),
            ('Books', '📚'),
            ('Beauty', '💄')
        ]
        c.executemany("INSERT INTO categories (name, icon) VALUES (?, ?)", categories)
        activity_logger.log_activity('DATABASE', 'Sample categories created', status='success')
    
    # Add sample products if none exist
    c.execute("SELECT COUNT(*) FROM products")
    if c.fetchone()[0] == 0:
        sample_products = [
            ('MacBook Pro 16"', 'Powerful laptop with M3 chip, 16GB RAM, 512GB SSD', 2499.99, 15, 1, 'https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=400', 4.8, 342),
            ('iPhone 15 Pro', 'Latest smartphone with A17 Pro chip and titanium design', 1199.99, 25, 1, 'https://images.unsplash.com/photo-1592286927505-2fd1cc0e8401?w=400', 4.7, 528),
            ('Sony WH-1000XM5', 'Industry-leading noise canceling wireless headphones', 399.99, 30, 1, 'https://images.unsplash.com/photo-1618366712010-f4ae9c647dcb?w=400', 4.9, 1203),
            ('Designer Leather Jacket', 'Premium quality genuine leather jacket', 299.99, 20, 2, 'https://images.unsplash.com/photo-1551028719-00167b16eac5?w=400', 4.6, 89),
            ('Nike Air Max', 'Comfortable running shoes with air cushioning', 149.99, 50, 2, 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=400', 4.5, 234),
            ('Espresso Coffee Maker', 'Professional grade home espresso machine', 499.99, 12, 3, 'https://images.unsplash.com/photo-1517668808822-9ebb02f2a0e6?w=400', 4.7, 156),
            ('Premium Yoga Mat', 'Non-slip yoga mat with carrying strap', 49.99, 100, 4, 'https://images.unsplash.com/photo-1601925260368-ae2f83cf8b7f?w=400', 4.8, 423),
            ('The Psychology of Money', 'Bestselling book on wealth and happiness', 24.99, 80, 5, 'https://images.unsplash.com/photo-1544947950-fa07a98d237f?w=400', 4.9, 2341),
        ]
        c.executemany("INSERT INTO products (name, description, price, stock, category_id, image_url, rating, reviews_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", sample_products)
        activity_logger.log_activity('DATABASE', 'Sample products created', status='success')
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect('ecommerce.db')
    conn.row_factory = sqlite3.Row
    return conn

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            log_unauthorized_access(request.path, 'login required')
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            log_unauthorized_access(request.path, 'admin')
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            log_unauthorized_access(request.path, 'admin')
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Main Routes
@app.route('/')
def index():
    try:
        search = request.args.get('search', '')
        category = request.args.get('category', '')
        sort_by = request.args.get('sort', 'newest')
        
        conn = get_db()
        
        # Get all categories
        categories = conn.execute('SELECT * FROM categories').fetchall()
        
        # Build query
        query = 'SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id WHERE 1=1'
        params = []
        
        if search:
            query += ' AND (p.name LIKE ? OR p.description LIKE ?)'
            params.extend([f'%{search}%', f'%{search}%'])
            activity_logger.log_activity('USER', f'Product search performed', details=f'Query: {search}', status='info')
        
        if category:
            query += ' AND p.category_id = ?'
            params.append(category)
        
        # Sorting
        if sort_by == 'price_low':
            query += ' ORDER BY p.price ASC'
        elif sort_by == 'price_high':
            query += ' ORDER BY p.price DESC'
        elif sort_by == 'rating':
            query += ' ORDER BY p.rating DESC'
        else:
            query += ' ORDER BY p.created_at DESC'
        
        products = conn.execute(query, params).fetchall()
        
        # Get featured products
        featured = conn.execute('SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id WHERE p.rating >= 4.5 ORDER BY p.rating DESC LIMIT 3').fetchall()
        
        conn.close()
        
        return render_template('index.html', 
                             products=products, 
                             featured=featured,
                             categories=categories,
                             search=search,
                             current_category=category,
                             sort_by=sort_by)
    except Exception as e:
        log_error('Page Load Error', f'Error loading index page: {str(e)}')
        flash('An error occurred while loading the page', 'danger')
        return render_template('index.html', products=[], featured=[], categories=[])

# Admin Users Route
@app.route('/admin/users')
@admin_required
def admin_users():
    try:
        # Get filter and sort parameters
        search = request.args.get('search', '')
        sort_by = request.args.get('sort', 'newest')
        
        conn = get_db()
        
        # Build query
        query = 'SELECT * FROM users WHERE 1=1'
        params = []
        
        if search:
            query += ' AND (username LIKE ? OR email LIKE ?)'
            search_param = f'%{search}%'
            params.extend([search_param, search_param])
        
        # Sort
        if sort_by == 'newest':
            query += ' ORDER BY created_at DESC'
        elif sort_by == 'oldest':
            query += ' ORDER BY created_at ASC'
        elif sort_by == 'name':
            query += ' ORDER BY username ASC'
        
        users = conn.execute(query, params).fetchall()
        
        # Get user statistics
        user_stats = conn.execute('''
            SELECT 
                COUNT(*) as total_users,
                SUM(CASE WHEN is_admin = 1 THEN 1 ELSE 0 END) as admin_count,
                SUM(CASE WHEN is_admin = 0 THEN 1 ELSE 0 END) as customer_count
            FROM users
        ''').fetchone()
        
        # Get orders count for each user
        users_with_orders = []
        for user in users:
            order_count = conn.execute('SELECT COUNT(*) as count FROM orders WHERE user_id = ?', (user['id'],)).fetchone()
            total_spent = conn.execute('SELECT SUM(total) as total FROM orders WHERE user_id = ?', (user['id'],)).fetchone()
            
            users_with_orders.append({
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'is_admin': user['is_admin'],
                'created_at': user['created_at'],
                'order_count': order_count['count'] if order_count else 0,
                'total_spent': total_spent['total'] if total_spent and total_spent['total'] else 0
            })
        
        conn.close()
        
        return render_template('admin/users.html', 
                             users=users_with_orders,
                             user_stats=user_stats,
                             search=search,
                             sort_by=sort_by)
    except Exception as e:
        log_error('Admin Users Error', f'Error loading users page: {str(e)}')
        flash('An error occurred while loading users', 'danger')
        return
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    try:
        conn = get_db()
        product = conn.execute('''SELECT p.*, c.name as category_name 
                                 FROM products p 
                                 LEFT JOIN categories c ON p.category_id = c.id 
                                 WHERE p.id = ?''', (product_id,)).fetchone()
        
        if not product:
            flash('Product not found', 'danger')
            return redirect(url_for('index'))
        
        # Log product view
        activity_logger.log_activity('USER', f'Viewed product', details=f'Product: {product["name"]} (ID: {product_id})', status='info')
        
        # Get related products
        related = conn.execute('''SELECT * FROM products 
                                 WHERE category_id = ? AND id != ? AND stock > 0 
                                 ORDER BY rating DESC LIMIT 4''', 
                              (product['category_id'], product_id)).fetchall()
        
        # Check if in wishlist
        in_wishlist = False
        if 'user_id' in session:
            check = conn.execute('SELECT * FROM wishlist WHERE user_id = ? AND product_id = ?',
                               (session['user_id'], product_id)).fetchone()
            in_wishlist = check is not None
        
        conn.close()
        
        return render_template('product_detail.html', 
                             product=product, 
                             related=related,
                             in_wishlist=in_wishlist)
    except Exception as e:
        log_error('Product View Error', f'Error viewing product {product_id}: {str(e)}')
        flash('An error occurred', 'danger')
        return redirect(url_for('index'))

# Auth Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            log_validation_error('login', 'empty credentials', 'Username and password required')
            flash('Please enter both username and password', 'danger')
            return render_template('login.html')
        
        try:
            conn = get_db()
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            conn.close()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                
                log_login_attempt(username, True)
                flash(f'Welcome back, {user["username"]}!', 'success')
                
                if user['is_admin']:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('index'))
            else:
                reason = 'User not found' if not user else 'Invalid password'
                log_login_attempt(username, False, reason)
                flash('Invalid username or password', 'danger')
        except Exception as e:
            log_error('Login Error', f'Error during login for user {username}: {str(e)}')
            flash('An error occurred during login', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        # Validation
        if not username or not email or not password:
            log_validation_error('registration', 'empty fields', 'All fields required')
            flash('All fields are required', 'danger')
            return render_template('register.html')
        
        if len(password) < 6:
            log_validation_error('registration', password, 'Password too short')
            flash('Password must be at least 6 characters long', 'danger')
            return render_template('register.html')
        
        conn = get_db()
        
        try:
            hashed_password = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                        (username, email, hashed_password))
            conn.commit()
            log_registration(username, email, True)
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            reason = 'Username already exists' if 'username' in str(e).lower() else 'Email already exists'
            log_registration(username, email, False, reason)
            flash('Username or email already exists', 'danger')
        except Exception as e:
            log_error('Registration Error', f'Error registering user {username}: {str(e)}')
            flash('An error occurred during registration', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    log_logout(username)
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

# Cart Routes
@app.route('/cart')
@login_required
def cart():
    try:
        if 'cart' not in session:
            session['cart'] = []
        
        conn = get_db()
        cart_items = []
        total = 0
        
        for item in session['cart']:
            product = conn.execute('SELECT * FROM products WHERE id = ?', (item['product_id'],)).fetchone()
            if product:
                item_total = product['price'] * item['quantity']
                cart_items.append({
                    'product': product,
                    'quantity': item['quantity'],
                    'total': item_total
                })
                total += item_total
        
        conn.close()
        
        return render_template('cart.html', 
                             cart_items=cart_items, 
                             total=total,
                             item_count=len(cart_items))
    except Exception as e:
        log_error('Cart Error', f'Error loading cart: {str(e)}')
        flash('An error occurred', 'danger')
        return redirect(url_for('index'))

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    try:
        quantity = int(request.form.get('quantity', 1))
        
        if quantity <= 0:
            log_validation_error('add_to_cart', quantity, 'Invalid quantity')
            flash('Invalid quantity', 'danger')
            return redirect(url_for('product_detail', product_id=product_id))
        
        # Get product info for logging
        conn = get_db()
        product = conn.execute('SELECT name, stock FROM products WHERE id = ?', (product_id,)).fetchone()
        conn.close()
        
        if not product:
            log_error('Cart Error', f'Product {product_id} not found')
            flash('Product not found', 'danger')
            return redirect(url_for('index'))
        
        if 'cart' not in session:
            session['cart'] = []
        
        # Check stock availability
        current_cart_qty = sum(item['quantity'] for item in session['cart'] if item['product_id'] == product_id)
        if current_cart_qty + quantity > product['stock']:
            log_validation_error('add_to_cart', quantity, f'Insufficient stock for product {product_id}')
            flash('Insufficient stock available', 'warning')
            return redirect(url_for('product_detail', product_id=product_id))
        
        # Check if product already in cart
        for item in session['cart']:
            if item['product_id'] == product_id:
                item['quantity'] += quantity
                session.modified = True
                log_cart_action('Cart updated', product['name'], quantity)
                flash('Cart updated', 'success')
                return redirect(url_for('cart'))
        
        # Add new item
        session['cart'].append({'product_id': product_id, 'quantity': quantity})
        session.modified = True
        log_cart_action('Item added to cart', product['name'], quantity)
        flash('Added to cart', 'success')
        return redirect(url_for('cart'))
    except ValueError:
        log_validation_error('add_to_cart', 'invalid quantity', 'Non-numeric quantity')
        flash('Invalid quantity', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))
    except Exception as e:
        log_error('Cart Error', f'Error adding product {product_id} to cart: {str(e)}')
        flash('An error occurred', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))

@app.route('/update_cart/<int:product_id>', methods=['POST'])
@login_required
def update_cart(product_id):
    try:
        quantity = int(request.form['quantity'])
        
        if quantity <= 0:
            log_validation_error('update_cart', quantity, 'Invalid quantity')
            return redirect(url_for('cart'))
        
        # Get product for logging
        conn = get_db()
        product = conn.execute('SELECT name FROM products WHERE id = ?', (product_id,)).fetchone()
        conn.close()
        
        for item in session['cart']:
            if item['product_id'] == product_id:
                old_qty = item['quantity']
                item['quantity'] = quantity
                session.modified = True
                if product:
                    log_cart_action('Cart quantity updated', product['name'], f'{old_qty} → {quantity}')
                break
        
        return redirect(url_for('cart'))
    except Exception as e:
        log_error('Cart Error', f'Error updating cart for product {product_id}: {str(e)}')
        return redirect(url_for('cart'))

@app.route('/remove_from_cart/<int:product_id>')
@login_required
def remove_from_cart(product_id):
    try:
        # Get product for logging
        conn = get_db()
        product = conn.execute('SELECT name FROM products WHERE id = ?', (product_id,)).fetchone()
        conn.close()
        
        session['cart'] = [item for item in session['cart'] if item['product_id'] != product_id]
        session.modified = True
        
        if product:
            log_cart_action('Item removed from cart', product['name'])
        flash('Item removed from cart', 'info')
        return redirect(url_for('cart'))
    except Exception as e:
        log_error('Cart Error', f'Error removing product {product_id} from cart: {str(e)}')
        return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if 'cart' not in session or not session['cart']:
        flash('Your cart is empty', 'warning')
        return redirect(url_for('cart'))
    
    if request.method == 'POST':
        try:
            shipping_address = request.form.get('shipping_address', '').strip()
            payment_method = request.form.get('payment_method', 'Cash on Delivery')
            
            if not shipping_address:
                log_validation_error('checkout', 'empty address', 'Shipping address required')
                flash('Shipping address is required', 'danger')
                return redirect(url_for('checkout'))
            
            conn = get_db()
            
            # Calculate total
            total = 0
            for item in session['cart']:
                product = conn.execute('SELECT price FROM products WHERE id = ?', (item['product_id'],)).fetchone()
                total += product['price'] * item['quantity']
            
            # Create order
            cursor = conn.execute('INSERT INTO orders (user_id, total, shipping_address, payment_method, status) VALUES (?, ?, ?, ?, ?)',
                                (session['user_id'], total, shipping_address, payment_method, 'pending'))
            order_id = cursor.lastrowid
            
            # Add order items and update stock
            for item in session['cart']:
                product = conn.execute('SELECT price, stock, name FROM products WHERE id = ?', (item['product_id'],)).fetchone()
                
                conn.execute('INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
                            (order_id, item['product_id'], item['quantity'], product['price']))
                
                # Update stock
                new_stock = product['stock'] - item['quantity']
                conn.execute('UPDATE products SET stock = ? WHERE id = ?', (new_stock, item['product_id']))
                
                log_database_change('products', 'Stock updated', item['product_id'], f'{product["name"]}: {product["stock"]} → {new_stock}')
            
            conn.commit()
            conn.close()
            
            # Log order creation
            log_order_action('Order placed', order_id, f'Total: ${total:.2f}, Payment: {payment_method}')
            
            # Clear cart
            session['cart'] = []
            session.modified = True
            
            # Check payment method
            if payment_method == 'Cash on Delivery':
                flash(f'Order placed successfully! Order ID: #{order_id}', 'success')
                return redirect(url_for('my_orders'))
            else:
                # Redirect to payment page for online payments
                log_payment_action('Payment page accessed', order_id, total, payment_method)
                return redirect(url_for('payment_page', order_id=order_id, amount=total, method=payment_method))
        except Exception as e:
            log_error('Checkout Error', f'Error processing checkout: {str(e)}')
            flash('An error occurred during checkout', 'danger')
            return redirect(url_for('cart'))
    
    # Calculate total for display
    try:
        conn = get_db()
        total = 0
        for item in session['cart']:
            product = conn.execute('SELECT price FROM products WHERE id = ?', (item['product_id'],)).fetchone()
            total += product['price'] * item['quantity']
        conn.close()
        
        return render_template('checkout.html', total=total)
    except Exception as e:
        log_error('Checkout Error', f'Error loading checkout page: {str(e)}')
        flash('An error occurred', 'danger')
        return redirect(url_for('cart'))

# Wishlist Routes
@app.route('/wishlist')
@login_required
def wishlist():
    try:
        conn = get_db()
        items = conn.execute('''SELECT p.* FROM products p 
                               JOIN wishlist w ON p.id = w.product_id 
                               WHERE w.user_id = ?''', (session['user_id'],)).fetchall()
        conn.close()
        return render_template('wishlist.html', items=items)
    except Exception as e:
        log_error('Wishlist Error', f'Error loading wishlist: {str(e)}')
        flash('An error occurred', 'danger')
        return render_template('wishlist.html', items=[])

@app.route('/add_to_wishlist/<int:product_id>')
@login_required
def add_to_wishlist(product_id):
    try:
        conn = get_db()
        product = conn.execute('SELECT name FROM products WHERE id = ?', (product_id,)).fetchone()
        
        # Check if already in wishlist
        existing = conn.execute('SELECT * FROM wishlist WHERE user_id = ? AND product_id = ?',
                              (session['user_id'], product_id)).fetchone()
        
        if not existing:
            conn.execute('INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)',
                        (session['user_id'], product_id))
            conn.commit()
            if product:
                activity_logger.log_activity('USER', 'Added to wishlist', details=f'Product: {product["name"]} (ID: {product_id})', status='info')
            flash('Added to wishlist', 'success')
        else:
            flash('Already in wishlist', 'info')
        
        conn.close()
        return redirect(url_for('product_detail', product_id=product_id))
    except Exception as e:
        log_error('Wishlist Error', f'Error adding product {product_id} to wishlist: {str(e)}')
        flash('An error occurred', 'danger')
        return redirect(url_for('product_detail', product_id=product_id))

@app.route('/remove_from_wishlist/<int:product_id>')
@login_required
def remove_from_wishlist(product_id):
    try:
        conn = get_db()
        product = conn.execute('SELECT name FROM products WHERE id = ?', (product_id,)).fetchone()
        
        conn.execute('DELETE FROM wishlist WHERE user_id = ? AND product_id = ?',
                    (session['user_id'], product_id))
        conn.commit()
        conn.close()
        
        if product:
            activity_logger.log_activity('USER', 'Removed from wishlist', details=f'Product: {product["name"]} (ID: {product_id})', status='info')
        flash('Removed from wishlist', 'info')
        return redirect(request.referrer or url_for('wishlist'))
    except Exception as e:
        log_error('Wishlist Error', f'Error removing product {product_id} from wishlist: {str(e)}')
        flash('An error occurred', 'danger')
        return redirect(url_for('wishlist'))

# Order Routes
@app.route('/my_orders')
@login_required
def my_orders():
    try:
        conn = get_db()
        orders = conn.execute('''SELECT o.*, 
                                       COUNT(oi.id) as item_count
                                FROM orders o
                                LEFT JOIN order_items oi ON o.id = oi.order_id
                                WHERE o.user_id = ?
                                GROUP BY o.id
                                ORDER BY o.created_at DESC''', 
                            (session['user_id'],)).fetchall()
        
        # Get items for each order
        orders_with_items = []
        for order in orders:
            items = conn.execute('''SELECT oi.*, p.name, p.image_url 
                                   FROM order_items oi 
                                   JOIN products p ON oi.product_id = p.id 
                                   WHERE oi.order_id = ?''', (order['id'],)).fetchall()
            orders_with_items.append({
                **dict(order),
                'items': items
            })
        
        conn.close()
        return render_template('my_orders.html', orders=orders_with_items)
    except Exception as e:
        log_error('Orders Error', f'Error loading user orders: {str(e)}')
        flash('An error occurred', 'danger')
        return render_template('my_orders.html', orders=[])

# Admin Routes
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        conn = get_db()
        
        # Get statistics
        total_products = conn.execute('SELECT COUNT(*) FROM products').fetchone()[0]
        total_orders = conn.execute('SELECT COUNT(*) FROM orders').fetchone()[0]
        total_users = conn.execute('SELECT COUNT(*) FROM users WHERE is_admin = 0').fetchone()[0]
        total_revenue = conn.execute('SELECT COALESCE(SUM(total), 0) FROM orders WHERE status != "cancelled"').fetchone()[0]
        
        # Recent orders
        recent_orders = conn.execute('''SELECT o.*, u.username 
                                       FROM orders o 
                                       JOIN users u ON o.user_id = u.id 
                                       ORDER BY o.created_at DESC LIMIT 5''').fetchall()
        
        # Top selling products
        top_products = conn.execute('''SELECT p.*, SUM(oi.quantity) as sold, SUM(oi.quantity * oi.price) as revenue
                                      FROM products p
                                      JOIN order_items oi ON p.id = oi.product_id
                                      GROUP BY p.id
                                      ORDER BY sold DESC
                                      LIMIT 5''').fetchall()
        
        # Low stock products
        low_stock = conn.execute('SELECT * FROM products WHERE stock < 10 ORDER BY stock ASC').fetchall()
        
        conn.close()
        
        return render_template('admin/dashboard.html',
                             total_products=total_products,
                             total_orders=total_orders,
                             total_users=total_users,
                             total_revenue=total_revenue,
                             recent_orders=recent_orders,
                             top_products=top_products,
                             low_stock=low_stock)
    except Exception as e:
        log_error('Admin Dashboard Error', f'Error loading dashboard: {str(e)}')
        flash('An error occurred', 'danger')
        return render_template('admin/dashboard.html', 
                             total_products=0, total_orders=0, total_users=0, 
                             total_revenue=0, recent_orders=[], top_products=[], low_stock=[])

@app.route('/admin/products')
@admin_required
def admin_products():
    try:
        conn = get_db()
        products = conn.execute('''SELECT p.*, c.name as category_name 
                                  FROM products p 
                                  LEFT JOIN categories c ON p.category_id = c.id 
                                  ORDER BY p.created_at DESC''').fetchall()
        conn.close()
        return render_template('admin/products.html', products=products)
    except Exception as e:
        log_error('Admin Products Error', f'Error loading products: {str(e)}')
        flash('An error occurred', 'danger')
        return render_template('admin/products.html', products=[])

@app.route('/admin/products/add', methods=['GET', 'POST'])
@admin_required
def admin_add_product():
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            price = float(request.form.get('price', 0))
            stock = int(request.form.get('stock', 0))
            category_id = int(request.form.get('category_id', 0))
            image_url = request.form.get('image_url', '').strip()
            
            # Validation
            if not name or not description or price <= 0 or stock < 0:
                log_validation_error('add_product', 'invalid data', 'Missing or invalid product data')
                flash('All fields are required with valid values', 'danger')
                return redirect(url_for('admin_add_product'))
            
            conn = get_db()
            cursor = conn.execute('''INSERT INTO products (name, description, price, stock, category_id, image_url) 
                                    VALUES (?, ?, ?, ?, ?, ?)''',
                                 (name, description, price, stock, category_id, image_url))
            product_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            log_product_action('Product added', product_id, name, f'Price: ${price}, Stock: {stock}')
            flash('Product added successfully', 'success')
            return redirect(url_for('admin_products'))
        except ValueError:
            log_validation_error('add_product', 'invalid number', 'Invalid price or stock value')
            flash('Invalid price or stock value', 'danger')
        except Exception as e:
            log_error('Add Product Error', f'Error adding product: {str(e)}')
            flash('An error occurred', 'danger')
    
    try:
        conn = get_db()
        categories = conn.execute('SELECT * FROM categories').fetchall()
        conn.close()
        return render_template('admin/add_product.html', categories=categories)
    except Exception as e:
        log_error('Add Product Error', f'Error loading add product page: {str(e)}')
        return render_template('admin/add_product.html', categories=[])

@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_product(product_id):
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            price = float(request.form.get('price', 0))
            stock = int(request.form.get('stock', 0))
            category_id = int(request.form.get('category_id', 0))
            image_url = request.form.get('image_url', '').strip()
            
            conn = get_db()
            old_product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
            
            conn.execute('''UPDATE products 
                           SET name = ?, description = ?, price = ?, stock = ?, category_id = ?, image_url = ?
                           WHERE id = ?''',
                        (name, description, price, stock, category_id, image_url, product_id))
            conn.commit()
            conn.close()
            
            changes = []
            if old_product:
                if old_product['price'] != price:
                    changes.append(f'Price: ${old_product["price"]} → ${price}')
                if old_product['stock'] != stock:
                    changes.append(f'Stock: {old_product["stock"]} → {stock}')
            
            log_product_action('Product updated', product_id, name, ', '.join(changes) if changes else 'Product details updated')
            flash('Product updated successfully', 'success')
            return redirect(url_for('admin_products'))
        except ValueError:
            log_validation_error('edit_product', 'invalid number', 'Invalid price or stock value')
            flash('Invalid price or stock value', 'danger')
        except Exception as e:
            log_error('Edit Product Error', f'Error editing product {product_id}: {str(e)}')
            flash('An error occurred', 'danger')
    
    try:
        conn = get_db()
        product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
        categories = conn.execute('SELECT * FROM categories').fetchall()
        conn.close()
        
        if not product:
            flash('Product not found', 'danger')
            return redirect(url_for('admin_products'))
        
        return render_template('admin/edit_product.html', product=product, categories=categories)
    except Exception as e:
        log_error('Edit Product Error', f'Error loading edit product page for {product_id}: {str(e)}')
        flash('An error occurred', 'danger')
        return redirect(url_for('admin_products'))

@app.route('/admin/products/delete/<int:product_id>')
@admin_required
def admin_delete_product(product_id):
    try:
        conn = get_db()
        product = conn.execute('SELECT name FROM products WHERE id = ?', (product_id,)).fetchone()
        
        conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
        conn.commit()
        conn.close()
        
        if product:
            log_product_action('Product deleted', product_id, product['name'])
        flash('Product deleted successfully', 'success')
    except Exception as e:
        log_error('Delete Product Error', f'Error deleting product {product_id}: {str(e)}')
        flash('An error occurred', 'danger')
    
    return redirect(url_for('admin_products'))

@app.route('/admin/orders')
@admin_required
def admin_orders():
    try:
        conn = get_db()
        orders = conn.execute('''SELECT o.*, u.username,
                                       COUNT(oi.id) as item_count
                                FROM orders o
                                JOIN users u ON o.user_id = u.id
                                LEFT JOIN order_items oi ON o.id = oi.order_id
                                GROUP BY o.id
                                ORDER BY o.created_at DESC''').fetchall()
        conn.close()
        return render_template('admin/orders.html', orders=orders)
    except Exception as e:
        log_error('Admin Orders Error', f'Error loading orders: {str(e)}')
        flash('An error occurred', 'danger')
        return render_template('admin/orders.html', orders=[])

@app.route('/admin/orders/<int:order_id>')
@admin_required
def admin_order_detail(order_id):
    try:
        conn = get_db()
        order = conn.execute('''SELECT o.*, u.username, u.email 
                               FROM orders o 
                               JOIN users u ON o.user_id = u.id 
                               WHERE o.id = ?''', (order_id,)).fetchone()
        
        items = conn.execute('''SELECT oi.*, p.name, p.image_url 
                               FROM order_items oi 
                               JOIN products p ON oi.product_id = p.id 
                               WHERE oi.order_id = ?''', (order_id,)).fetchall()
        conn.close()
        
        if not order:
            flash('Order not found', 'danger')
            return redirect(url_for('admin_orders'))
        
        return render_template('admin/order_detail.html', order=order, items=items)
    except Exception as e:
        log_error('Admin Order Detail Error', f'Error loading order {order_id}: {str(e)}')
        flash('An error occurred', 'danger')
        return redirect(url_for('admin_orders'))

@app.route('/admin/orders/update_status/<int:order_id>', methods=['POST'])
@admin_required
def admin_update_order_status(order_id):
    try:
        status = request.form.get('status', 'pending')
        
        conn = get_db()
        old_order = conn.execute('SELECT status FROM orders WHERE id = ?', (order_id,)).fetchone()
        
        conn.execute('UPDATE orders SET status = ? WHERE id = ?', (status, order_id))
        conn.commit()
        conn.close()
        
        if old_order:
            log_admin_order_update(order_id, old_order['status'], status, session.get('username', 'admin'))
        
        flash('Order status updated successfully', 'success')
    except Exception as e:
        log_error('Update Order Status Error', f'Error updating order {order_id} status: {str(e)}')
        flash('An error occurred', 'danger')
    
    return redirect(url_for('admin_order_detail', order_id=order_id))

# Admin Logs Route
@app.route('/admin/logs')
@admin_required
def admin_logs():
    try:
        # Get filter parameters
        filter_type = request.args.get('log_type', '')
        filter_status = request.args.get('status', '')
        limit = int(request.args.get('limit', 100))
        
        # Get logs
        logs = activity_logger.get_all_logs(limit=limit, log_type=filter_type if filter_type else None, status=filter_status if filter_status else None)
        
        # Get statistics
        stats = activity_logger.get_log_statistics()
        
        return render_template('admin/admin_logs.html', 
                             logs=logs, 
                             stats=stats,
                             filter_type=filter_type,
                             filter_status=filter_status,
                             limit=limit)
    except Exception as e:
        log_error('Admin Logs Error', f'Error loading logs page: {str(e)}')
        flash('An error occurred while loading logs', 'danger')
        return render_template('admin/admin_logs.html', logs=[], stats={})

# API endpoints for AJAX
@app.route('/api/cart/count')
@login_required
def get_cart_count():
    cart = session.get('cart', [])
    return jsonify({'count': len(cart)})

# Payment Routes
@app.route('/payment')
@login_required
def payment_page():
    try:
        order_id = request.args.get('order_id')
        amount = float(request.args.get('amount', 0))
        payment_method = request.args.get('method', 'UPI')
        
        # Convert USD to INR (approximate rate: 1 USD = 83 INR)
        amount_inr = amount * 83
        
        return render_template('payment.html', 
                             order_id=order_id, 
                             amount=amount_inr, 
                             payment_method=payment_method)
    except Exception as e:
        log_error('Payment Page Error', f'Error loading payment page: {str(e)}')
        flash('An error occurred', 'danger')
        return redirect(url_for('my_orders'))

@app.route('/verify_payment', methods=['POST'])
@login_required
def verify_payment():
    try:
        order_id = request.form.get('order_id')
        payment_method = request.form.get('payment_method')
        transaction_id = request.form.get('transaction_id', 'N/A')
        
        # In a real application, you would verify the payment with payment gateway API
        # For demo purposes, we'll just mark the order as processing
        
        conn = get_db()
        order = conn.execute('SELECT total FROM orders WHERE id = ?', (order_id,)).fetchone()
        conn.execute('UPDATE orders SET status = ? WHERE id = ?', ('processing', order_id))
        conn.commit()
        conn.close()
        
        if order:
            log_payment_action('Payment verified', order_id, order['total'], payment_method, 'success')
        
        flash(f'Payment verified! Your order #{order_id} is being processed. Transaction ID: {transaction_id}', 'success')
        return redirect(url_for('my_orders'))
    except Exception as e:
        log_error('Payment Verification Error', f'Error verifying payment: {str(e)}')
        flash('An error occurred during payment verification', 'danger')
        return redirect(url_for('my_orders'))

# Cancel Order Route
@app.route('/cancel_order/<int:order_id>')
@login_required
def cancel_order(order_id):
    try:
        conn = get_db()
        
        # Verify order belongs to user
        order = conn.execute('SELECT * FROM orders WHERE id = ? AND user_id = ?', 
                            (order_id, session['user_id'])).fetchone()
        
        if not order:
            log_security_event('Unauthorized order cancellation attempt', f'User {session.get("username")} attempted to cancel order {order_id}')
            flash('Order not found', 'danger')
            conn.close()
            return redirect(url_for('my_orders'))
        
        # Only allow cancellation for pending/processing orders
        if order['status'] not in ['pending', 'processing']:
            log_validation_error('cancel_order', order['status'], f'Cannot cancel order in status: {order["status"]}')
            flash('This order cannot be cancelled', 'warning')
            conn.close()
            return redirect(url_for('my_orders'))
        
        # Get order items to restore stock
        order_items = conn.execute('''SELECT oi.product_id, oi.quantity, p.name 
                                      FROM order_items oi
                                      JOIN products p ON oi.product_id = p.id
                                      WHERE oi.order_id = ?''', (order_id,)).fetchall()
        
        # Restore stock for each product
        for item in order_items:
            conn.execute('''UPDATE products 
                           SET stock = stock + ? 
                           WHERE id = ?''', (item['quantity'], item['product_id']))
            log_database_change('products', 'Stock restored', item['product_id'], f'{item["name"]}: +{item["quantity"]} units')
        
        # Update order status to cancelled
        conn.execute('UPDATE orders SET status = ? WHERE id = ?', ('cancelled', order_id))
        conn.commit()
        conn.close()
        
        log_order_action('Order cancelled', order_id, f'Stock restored for {len(order_items)} products')
        flash(f'Order #{order_id} has been cancelled successfully', 'success')
        return redirect(url_for('my_orders'))
    except Exception as e:
        log_error('Cancel Order Error', f'Error cancelling order {order_id}: {str(e)}')
        flash('An error occurred', 'danger')
        return redirect(url_for('my_orders'))

if __name__ == '__main__':
    init_db()
    activity_logger.log_activity('SYSTEM', 'Application started', status='success')
    app.run(debug=True, host='0.0.0.0', port=5000)