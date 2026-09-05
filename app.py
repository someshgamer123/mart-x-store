import os
import time
import random
import string
import mimetypes
from datetime import datetime
from functools import wraps
from bson import ObjectId
from dotenv import load_dotenv
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, jsonify, abort, Response, stream_with_context
)
from pymongo import MongoClient, ASCENDING, DESCENDING
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(32))

SITE_NAME = "Mart X Store"
MAX_DOWNLOAD_LIMIT = 3
DEFAULT_STORE_REDIRECT = "https://t.me/"

# Upload Configuration (Up to 350 MB to safely support 300 MB files)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 350 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ---------------- MongoDB Connection ---------------- #

MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/mart_x_store')
client = MongoClient(MONGO_URI, authSource="admin")
db = client['mart_x_store']

# Collections
admins_col = db['admins']
items_col = db['items']
links_col = db['share_links']

# Indexes
links_col.create_index([('link_code', ASCENDING)], unique=True)
links_col.create_index([('item_id', ASCENDING)])
items_col.create_index([('created_at', DESCENDING)])

# Default Admin Init
default_admin = admins_col.find_one({})
if not default_admin:
    default_pw_hash = generate_password_hash('admin123')
    default_secret_hash = generate_password_hash('889900')
    admins_col.insert_one({
        'username': 'admin',
        'password_hash': default_pw_hash,
        'secret_code_hash': default_secret_hash,
        'saved_device_tokens': [],
        'default_redirect_url': DEFAULT_STORE_REDIRECT,
        'created_at': datetime.utcnow()
    })

# ---------------- Helper Functions ---------------- #

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_custom_password(length=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))

def generate_unique_link_code(length=12):
    chars = string.ascii_letters + string.digits
    while True:
        code = ''.join(random.choice(chars) for _ in range(length))
        if not links_col.find_one({'link_code': code}):
            return code

def generate_device_token(length=48):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ---------------- Root & Favicon Routes ---------------- #

@app.route('/')
def home():
    return redirect(url_for('admin_login'))

@app.route('/favicon.ico')
def favicon():
    return ('', 204)

# ---------------- Admin Auth & 2-Step Login ---------------- #

@app.route('/admin/login')
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    return render_template('login.html', site_name=SITE_NAME)

@app.route('/api/verify-secret', methods=['POST'])
def verify_secret():
    data = request.get_json() or {}
    secret_code = data.get('secret_code', '').strip()
    device_token = data.get('device_token', '').strip()

    admin = admins_col.find_one({})
    if not admin:
        return jsonify({'success': False, 'message': 'Admin record missing.'}), 500

    secret_hash = admin.get('secret_code_hash')
    if not secret_hash or not check_password_hash(secret_hash, secret_code):
        return jsonify({'success': False, 'message': 'Invalid Secret Access Key.'}), 401

    saved_tokens = admin.get('saved_device_tokens', [])
    if device_token and device_token in saved_tokens:
        session['admin_logged_in'] = True
        session['admin_username'] = admin['username']
        return jsonify({
            'success': True,
            'auto_login': True,
            'message': 'Device recognized. Access granted!'
        })

    return jsonify({
        'success': True,
        'auto_login': False,
        'message': 'Secret key verified. Please enter credentials.'
    })

@app.route('/api/login-credentials', methods=['POST'])
def login_credentials():
    data = request.get_json() or {}
    secret_code = data.get('secret_code', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    save_login = data.get('save_login', False)

    admin = admins_col.find_one({})
    if not admin:
        return jsonify({'success': False, 'message': 'System error'}), 500

    secret_hash = admin.get('secret_code_hash')
    if not secret_hash or not check_password_hash(secret_hash, secret_code):
        return jsonify({'success': False, 'message': 'Secret verification expired.'}), 401

    if admin.get('username') != username or not check_password_hash(admin.get('password_hash', ''), password):
        return jsonify({'success': False, 'message': 'Incorrect username or password.'}), 401

    session['admin_logged_in'] = True
    session['admin_username'] = username

    new_device_token = None
    if save_login:
        new_device_token = generate_device_token()
        admins_col.update_one(
            {'_id': admin['_id']},
            {'$push': {'saved_device_tokens': new_device_token}}
        )

    return jsonify({
        'success': True,
        'device_token': new_device_token,
        'message': 'Login successful!'
    })

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

# ---------------- Admin Settings ---------------- #

@app.route('/admin/update-settings', methods=['POST'])
@login_required
def update_settings():
    data = request.get_json() or {}
    current_password = data.get('current_password', '').strip()
    new_username = data.get('new_username', '').strip()
    new_password = data.get('new_password', '').strip()
    new_secret_code = data.get('new_secret_code', '').strip()
    default_redirect = data.get('default_redirect_url', '').strip()

    admin = admins_col.find_one({'username': session['admin_username']})
    if not admin or not check_password_hash(admin.get('password_hash', ''), current_password):
        return jsonify({'success': False, 'message': 'Current password does not match.'}), 400

    updates = {}
    if new_username and len(new_username) >= 3:
        updates['username'] = new_username
        session['admin_username'] = new_username

    if new_password:
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': 'New password must be at least 6 characters.'}), 400
        updates['password_hash'] = generate_password_hash(new_password)

    if new_secret_code:
        if len(new_secret_code) < 4:
            return jsonify({'success': False, 'message': 'Secret code must be at least 4 digits.'}), 400
        updates['secret_code_hash'] = generate_password_hash(new_secret_code)

    if default_redirect:
        updates['default_redirect_url'] = default_redirect

    if not updates:
        return jsonify({'success': False, 'message': 'No changes provided.'}), 400

    admins_col.update_one({'_id': admin['_id']}, {'$set': updates})
    return jsonify({'success': True, 'message': 'Settings updated successfully!'})

# ---------------- Admin Dashboard, Uploads & Edit Item ---------------- #

@app.route('/admin')
@login_required
def admin_dashboard():
    items = list(items_col.find().sort('created_at', DESCENDING))
    
    item_display = []
    for item in items:
        str_id = str(item['_id'])
        total_links = links_col.count_documents({'item_id': item['_id']})
        latest_link = links_col.find_one({'item_id': item['_id']}, sort=[('created_at', DESCENDING)])
        
        downloads_used = latest_link.get('download_count', 0) if latest_link else 0
        
        item_display.append({
            'id': str_id,
            'name': item.get('name', 'Untitled'),
            'logo_url': item.get('logo_url', ''),
            'redirect_url': item.get('redirect_url', ''),
            'threshold_mb': item.get('threshold_mb', 1.0),
            'item_type': item['item_type'],
            'file_size': item.get('file_size', 0),
            'total_links': total_links,
            'downloads_used': downloads_used,
            'max_limit': MAX_DOWNLOAD_LIMIT,
            'latest_link_code': latest_link['link_code'] if latest_link else None,
            'latest_password': latest_link['password'] if latest_link else None,
        })
        
    admin = admins_col.find_one({'username': session['admin_username']})
    current_user = admin['username'] if admin else session.get('admin_username', 'admin')
    curr_redirect = admin.get('default_redirect_url', DEFAULT_STORE_REDIRECT) if admin else DEFAULT_STORE_REDIRECT
    
    return render_template(
        'admin.html',
        site_name=SITE_NAME,
        items=item_display,
        current_username=current_user,
        default_redirect_url=curr_redirect,
        host_url=request.host_url
    )

@app.route('/admin/upload', methods=['POST'])
@login_required
def upload_item():
    upload_type = request.form.get('upload_type')
    custom_display_name = request.form.get('display_name', '').strip()
    logo_url = request.form.get('logo_url', '').strip()
    redirect_url = request.form.get('redirect_url', '').strip()
    
    # Download Threshold in MB (default: 1.0 MB)
    try:
        threshold_mb = float(request.form.get('threshold_mb', 1.0))
    except (ValueError, TypeError):
        threshold_mb = 1.0
        
    if threshold_mb < 0.01:
        threshold_mb = 0.01
    
    if upload_type == 'file':
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'Please select a file.'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file chosen.'}), 400
            
        orig_name = secure_filename(file.filename)
        _, ext = os.path.splitext(orig_name)
        prefix = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        saved_filename = f"{prefix}_{orig_name}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
        file.save(save_path)
        
        file_size = os.path.getsize(save_path)
        display_name = custom_display_name if custom_display_name else orig_name
        
        item_doc = {
            'item_type': 'file',
            'name': display_name,
            'logo_url': logo_url,
            'redirect_url': redirect_url,
            'threshold_mb': threshold_mb,
            'file_extension': ext,
            'file_path': saved_filename,
            'file_size': file_size,
            'created_at': datetime.utcnow()
        }
        res = items_col.insert_one(item_doc)
        item_id = res.inserted_id
        
    elif upload_type == 'link':
        url = request.form.get('url', '').strip()
        display_name = custom_display_name if custom_display_name else (url[:35] + '...')
        if not url:
            return jsonify({'success': False, 'message': 'Destination URL is required.'}), 400
            
        item_doc = {
            'item_type': 'link',
            'name': display_name,
            'logo_url': logo_url,
            'redirect_url': redirect_url,
            'threshold_mb': threshold_mb,
            'external_url': url,
            'file_size': 0,
            'created_at': datetime.utcnow()
        }
        res = items_col.insert_one(item_doc)
        item_id = res.inserted_id
    else:
        return jsonify({'success': False, 'message': 'Invalid upload type.'}), 400

    link_code = generate_unique_link_code()
    custom_pass = generate_custom_password()
    
    links_col.insert_one({
        'item_id': item_id,
        'link_code': link_code,
        'password': custom_pass,
        'download_count': 0,
        'created_at': datetime.utcnow()
    })
    
    return jsonify({
        'success': True,
        'message': 'Upload completed successfully!',
        'item_id': str(item_id),
        'link_code': link_code,
        'password': custom_pass,
        'full_link': f"{request.host_url}v/{link_code}"
    })

# ---------------- EDIT ITEM ROUTE ---------------- #
@app.route('/admin/edit-item/<item_id>', methods=['POST'])
@login_required
def edit_item(item_id):
    try:
        obj_id = ObjectId(item_id)
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID.'}), 400

    data = request.get_json() or {}
    name = data.get('name', '').strip()
    logo_url = data.get('logo_url', '').strip()
    redirect_url = data.get('redirect_url', '').strip()
    
    try:
        threshold_mb = float(data.get('threshold_mb', 1.0))
    except (ValueError, TypeError):
        threshold_mb = 1.0
        
    if threshold_mb < 0.01:
        threshold_mb = 0.01

    if not name:
        return jsonify({'success': False, 'message': 'Name cannot be empty.'}), 400

    items_col.update_one(
        {'_id': obj_id},
        {'$set': {
            'name': name,
            'logo_url': logo_url,
            'redirect_url': redirect_url,
            'threshold_mb': threshold_mb
        }}
    )

    return jsonify({'success': True, 'message': 'File details updated successfully!'})

@app.route('/admin/recreate-link/<item_id>', methods=['POST'])
@login_required
def recreate_link(item_id):
    try:
        obj_id = ObjectId(item_id)
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID.'}), 400
        
    item = items_col.find_one({'_id': obj_id})
    if not item:
        return jsonify({'success': False, 'message': 'Item not found.'}), 404
        
    new_code = generate_unique_link_code()
    new_pass = generate_custom_password()
    
    links_col.insert_one({
        'item_id': obj_id,
        'link_code': new_code,
        'password': new_pass,
        'download_count': 0,
        'created_at': datetime.utcnow()
    })
    
    total_links = links_col.count_documents({'item_id': obj_id})
    
    return jsonify({
        'success': True,
        'item_id': str(item_id),
        'link_code': new_code,
        'password': new_pass,
        'total_links': total_links,
        'downloads_used': 0,
        'max_limit': MAX_DOWNLOAD_LIMIT,
        'full_link': f"{request.host_url}v/{new_code}",
        'message': 'New link & password created! (Old links still work 100%)'
    })

@app.route('/admin/delete-file/<item_id>', methods=['POST'])
@login_required
def delete_file(item_id):
    try:
        obj_id = ObjectId(item_id)
    except Exception:
        return jsonify({'success': False, 'message': 'Invalid ID.'}), 400

    item = items_col.find_one({'_id': obj_id})
    if item:
        if item.get('item_type') == 'file' and item.get('file_path'):
            disk_path = os.path.join(app.config['UPLOAD_FOLDER'], item['file_path'])
            if os.path.exists(disk_path):
                try:
                    os.remove(disk_path)
                except Exception:
                    pass
        links_col.delete_many({'item_id': obj_id})
        items_col.delete_one({'_id': obj_id})
        
    return jsonify({'success': True, 'message': 'Resource permanently deleted.'})

# ---------------- Buyer / User Portal ---------------- #

@app.route('/v/<link_code>')
def view_share_page(link_code):
    link = links_col.find_one({'link_code': link_code})
    if not link:
        abort(404)
        
    item = items_col.find_one({'_id': link['item_id']})
    if not item:
        abort(404)
        
    admin = admins_col.find_one({})
    fallback_redirect = admin.get('default_redirect_url', DEFAULT_STORE_REDIRECT) if admin else DEFAULT_STORE_REDIRECT
    buy_redirect = item.get('redirect_url') or fallback_redirect
    
    download_count = link.get('download_count', 0)
    is_expired = download_count >= MAX_DOWNLOAD_LIMIT
    
    return render_template(
        'share.html',
        site_name=SITE_NAME,
        link_code=link_code,
        item=item,
        download_count=download_count,
        max_limit=MAX_DOWNLOAD_LIMIT,
        is_expired=is_expired,
        buy_redirect=buy_redirect
    )

@app.route('/api/verify-password', methods=['POST'])
def verify_password():
    data = request.get_json() or {}
    link_code = data.get('link_code', '').strip()
    entered_password = data.get('password', '').strip()
    
    link = links_col.find_one({'link_code': link_code})
    if not link:
        return jsonify({'success': False, 'message': 'Invalid link code.'}), 404
        
    item = items_col.find_one({'_id': link['item_id']})
    if not item:
        return jsonify({'success': False, 'message': 'Item missing'}), 404

    admin = admins_col.find_one({})
    fallback_redirect = admin.get('default_redirect_url', DEFAULT_STORE_REDIRECT) if admin else DEFAULT_STORE_REDIRECT
    buy_redirect = item.get('redirect_url') or fallback_redirect

    download_count = link.get('download_count', 0)
    if download_count >= MAX_DOWNLOAD_LIMIT:
        return jsonify({
            'success': False,
            'limit_exceeded': True,
            'buy_redirect': buy_redirect,
            'message': f'Access Denied: Download limit reached ({MAX_DOWNLOAD_LIMIT}/{MAX_DOWNLOAD_LIMIT} used).'
        }), 403

    if link['password'] != entered_password:
        return jsonify({'success': False, 'message': 'Incorrect password key. Access denied.'}), 401
    
    session[f"auth_{link_code}"] = True
    
    stored_path = item.get('file_path', '')
    mime_type, _ = mimetypes.guess_type(stored_path)
    remaining_downloads = max(0, MAX_DOWNLOAD_LIMIT - download_count)
    
    return jsonify({
        'success': True,
        'item_type': item['item_type'],
        'name': item['name'],
        'logo_url': item.get('logo_url', ''),
        'file_size': item['file_size'],
        'download_count': download_count,
        'remaining_downloads': remaining_downloads,
        'max_limit': MAX_DOWNLOAD_LIMIT,
        'external_url': item.get('external_url'),
        'mime_type': mime_type or 'application/octet-stream',
        'download_url': url_for('download_item', link_code=link_code)
    })

# ---------------- DOWNLOAD STREAM WITH ACCURATE THRESHOLD TRACKING ---------------- #
@app.route('/download/<link_code>')
def download_item(link_code):
    if not session.get(f"auth_{link_code}"):
        return abort(403)
        
    link = links_col.find_one({'link_code': link_code})
    if not link:
        abort(404)
        
    download_count = link.get('download_count', 0)
    if download_count >= MAX_DOWNLOAD_LIMIT:
        item = items_col.find_one({'_id': link['item_id']})
        admin = admins_col.find_one({})
        buy_redirect = (item.get('redirect_url') if item else None) or (admin.get('default_redirect_url') if admin else DEFAULT_STORE_REDIRECT)
        return redirect(buy_redirect)

    item = items_col.find_one({'_id': link['item_id']})
    if not item:
        abort(404)

    if item['item_type'] == 'link':
        # Links count when clicked directly
        links_col.update_one({'_id': link['_id']}, {'$inc': {'download_count': 1}})
        return redirect(item['external_url'])

    disk_path = os.path.join(app.config['UPLOAD_FOLDER'], item['file_path'])
    if not os.path.exists(disk_path):
        abort(404)

    total_file_size = os.path.getsize(disk_path)
    ext = item.get('file_extension', '')
    download_filename = item['name']
    if ext and not download_filename.endswith(ext):
        download_filename = f"{download_filename}{ext}"

    # Calculate threshold in bytes (from Admin MB setting)
    threshold_mb = float(item.get('threshold_mb', 1.0))
    threshold_bytes = int(threshold_mb * 1024 * 1024)
    
    # If the total file is smaller than threshold, trigger count at 50% of file size
    if threshold_bytes > total_file_size:
        threshold_bytes = max(1024, int(total_file_size * 0.5))

    link_id = link['_id']
    cooldown_key = f"last_count_{link_code}"

    # Stream generator with exact MB threshold detection
    def stream_file_with_threshold():
        bytes_sent = 0
        threshold_triggered = False
        with open(disk_path, 'rb') as f:
            while True:
                chunk = f.read(128 * 1024)  # 128 KB chunks
                if not chunk:
                    break
                bytes_sent += len(chunk)

                # TRIGGER COUNT ONLY WHEN THRESHOLD MB IS REACHED IN BROWSER
                if not threshold_triggered and bytes_sent >= threshold_bytes:
                    now = time.time()
                    last_time = session.get(cooldown_key, 0)
                    # 15s Cooldown prevents mobile browsers/download managers multi-request false count
                    if (now - last_time) > 15:
                        links_col.update_one({'_id': link_id}, {'$inc': {'download_count': 1}})
                        session[cooldown_key] = now
                    threshold_triggered = True

                yield chunk

    response = Response(
        stream_with_context(stream_file_with_threshold()),
        mimetype='application/octet-stream'
    )
    response.headers['Content-Disposition'] = f'attachment; filename="{download_filename}"'
    response.headers['Content-Length'] = str(total_file_size)
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
