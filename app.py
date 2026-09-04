import os
import random
import string
import mimetypes
from datetime import datetime
from functools import wraps
from bson import ObjectId
from dotenv import load_dotenv
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, jsonify, send_from_directory, abort
)
from pymongo import MongoClient, ASCENDING, DESCENDING
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(32))

SITE_NAME = "Mart X Store"

# File Upload Settings: 350 MB limit (safely supports 1 KB to 300 MB files)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 350 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ---------------- MongoDB Connection ---------------- #

MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/mart_x_store')

# Explicitly authenticating against admin database for MongoDB Atlas
client = MongoClient(MONGO_URI, authSource="admin")
db = client['mart_x_store']

# Collections
admins_col = db['admins']
items_col = db['items']
links_col = db['share_links']

# Indexes for High Performance
links_col.create_index([('link_code', ASCENDING)], unique=True)
links_col.create_index([('item_id', ASCENDING)])
items_col.create_index([('created_at', DESCENDING)])

# Initialize Default Admin if not present
if admins_col.count_documents({'username': 'admin'}) == 0:
    default_hash = generate_password_hash('ChangeThisPasswordImmediately123!')
    admins_col.insert_one({
        'username': 'admin',
        'password_hash': default_hash,
        'created_at': datetime.utcnow()
    })

# ---------------- Helper Functions ---------------- #

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_custom_password(length=10):
    """Format: 10 lowercase letters, e.g. aoudfnegcu"""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))

def generate_unique_link_code(length=12):
    chars = string.ascii_letters + string.digits
    while True:
        code = ''.join(random.choice(chars) for _ in range(length))
        if not links_col.find_one({'link_code': code}):
            return code

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ---------------- Admin Auth Routes ---------------- #

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        admin = admins_col.find_one({'username': username})
        if admin and check_password_hash(admin['password_hash'], password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        return render_template('login.html', site_name=SITE_NAME, error='Invalid credentials')
        
    return render_template('login.html', site_name=SITE_NAME)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin/change-password', methods=['POST'])
@login_required
def change_admin_password():
    current_password = request.form.get('current_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    
    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'New password must be at least 6 characters.'}), 400
        
    admin = admins_col.find_one({'username': session['admin_username']})
    if not admin or not check_password_hash(admin['password_hash'], current_password):
        return jsonify({'success': False, 'message': 'Incorrect current password.'}), 400
        
    new_hash = generate_password_hash(new_password)
    admins_col.update_one({'_id': admin['_id']}, {'$set': {'password_hash': new_hash}})
    
    return jsonify({'success': True, 'message': 'Master password changed successfully.'})

# ---------------- Admin Management Routes ---------------- #

@app.route('/admin')
@login_required
def admin_dashboard():
    items = list(items_col.find().sort('created_at', DESCENDING))
    
    # Fetch and group all links by item_id
    all_links = list(links_col.find().sort('created_at', DESCENDING))
    item_links = {}
    for l in all_links:
        s_id = str(l['item_id'])
        item_links.setdefault(s_id, []).append(l)
        
    return render_template(
        'admin.html',
        site_name=SITE_NAME,
        items=items,
        item_links=item_links,
        host_url=request.host_url
    )

@app.route('/admin/upload', methods=['POST'])
@login_required
def upload_item():
    upload_type = request.form.get('upload_type')
    
    if upload_type == 'file':
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file received'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file chosen'}), 400
            
        orig_name = secure_filename(file.filename)
        prefix = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        saved_filename = f"{prefix}_{orig_name}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
        file.save(save_path)
        
        file_size = os.path.getsize(save_path)
        item_doc = {
            'item_type': 'file',
            'name': orig_name,
            'file_path': saved_filename,
            'file_size': file_size,
            'created_at': datetime.utcnow()
        }
        res = items_col.insert_one(item_doc)
        item_id = res.inserted_id
        
    elif upload_type == 'link':
        url = request.form.get('url', '').strip()
        name = request.form.get('name', '').strip() or url
        if not url:
            return jsonify({'success': False, 'message': 'Destination URL is required'}), 400
            
        item_doc = {
            'item_type': 'link',
            'name': name,
            'external_url': url,
            'file_size': 0,
            'created_at': datetime.utcnow()
        }
        res = items_col.insert_one(item_doc)
        item_id = res.inserted_id
    else:
        return jsonify({'success': False, 'message': 'Invalid upload type'}), 400

    # Auto-generate unique link & custom 10-character password for this item
    link_code = generate_unique_link_code()
    custom_pass = generate_custom_password()
    
    links_col.insert_one({
        'item_id': item_id,
        'link_code': link_code,
        'password': custom_pass,
        'created_at': datetime.utcnow()
    })
    
    return jsonify({
        'success': True,
        'message': 'Upload completed successfully!',
        'link_code': link_code,
        'password': custom_pass,
        'full_link': f"{request.host_url}v/{link_code}"
    })

@app.route('/admin/recreate-link/<item_id>', methods=['POST'])
@login_required
def recreate_link(item_id):
    try:
        obj_id = ObjectId(item_id)
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400
        
    item = items_col.find_one({'_id': obj_id})
    if not item:
        return jsonify({'success': False, 'message': 'Item not found'}), 404
        
    # Generate new link & pass while keeping all previous links completely active
    new_code = generate_unique_link_code()
    new_pass = generate_custom_password()
    
    links_col.insert_one({
        'item_id': obj_id,
        'link_code': new_code,
        'password': new_pass,
        'created_at': datetime.utcnow()
    })
    
    return jsonify({
        'success': True,
        'link_code': new_code,
        'password': new_pass,
        'full_link': f"{request.host_url}v/{new_code}"
    })

@app.route('/admin/delete-file/<item_id>', methods=['POST'])
@login_required
def delete_file(item_id):
    try:
        obj_id = ObjectId(item_id)
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID'}), 400

    item = items_col.find_one({'_id': obj_id})
    if item:
        if item.get('item_type') == 'file' and item.get('file_path'):
            disk_path = os.path.join(app.config['UPLOAD_FOLDER'], item['file_path'])
            if os.path.exists(disk_path):
                try:
                    os.remove(disk_path)
                except Exception:
                    pass
        # Delete item and all its associated links from MongoDB
        links_col.delete_many({'item_id': obj_id})
        items_col.delete_one({'_id': obj_id})
        
    return jsonify({'success': True, 'message': 'File and associated links permanently deleted.'})

# ---------------- User / Buyer Portal ---------------- #

@app.route('/v/<link_code>')
def view_share_page(link_code):
    link = links_col.find_one({'link_code': link_code})
    if not link:
        abort(404)
        
    item = items_col.find_one({'_id': link['item_id']})
    if not item:
        abort(404)
        
    return render_template(
        'share.html',
        site_name=SITE_NAME,
        link_code=link_code,
        item=item
    )

@app.route('/api/verify-password', methods=['POST'])
def verify_password():
    data = request.get_json() or {}
    link_code = data.get('link_code', '').strip()
    entered_password = data.get('password', '').strip()
    
    link = links_col.find_one({'link_code': link_code})
    if not link or link['password'] != entered_password:
        return jsonify({'success': False, 'message': 'Incorrect password. Access denied.'}), 401
    
    item = items_col.find_one({'_id': link['item_id']})
    if not item:
        return jsonify({'success': False, 'message': 'Item missing'}), 404
        
    # Store access grant in session for authorized download
    session[f"auth_{link_code}"] = True
    
    mime_type, _ = mimetypes.guess_type(item['name'])
    return jsonify({
        'success': True,
        'item_type': item['item_type'],
        'name': item['name'],
        'file_size': item['file_size'],
        'external_url': item.get('external_url'),
        'mime_type': mime_type or 'application/octet-stream',
        'download_url': url_for('download_item', link_code=link_code)
    })

@app.route('/download/<link_code>')
def download_item(link_code):
    if not session.get(f"auth_{link_code}"):
        return abort(403)
        
    link = links_col.find_one({'link_code': link_code})
    if not link:
        abort(404)
        
    item = items_col.find_one({'_id': link['item_id']})
    if not item:
        abort(404)
        
    if item['item_type'] == 'link':
        return redirect(item['external_url'])
        
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        item['file_path'],
        as_attachment=True,
        download_name=item['name']
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
