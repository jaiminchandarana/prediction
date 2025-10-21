from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
import bcrypt
import jwt
import datetime
from functools import wraps
import traceback

app = Flask(__name__)
CORS(app)

# Secret key for JWT
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# Database connection
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host='localhost',
            database='disease_prediction',
            user='postgres',
            password='JDCpostgres.@'
        )
        return conn
    except Exception as e:
        print(f"Database connection error: {str(e)}")
        return None

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'success': False, 'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Helper function to generate JWT token
def generate_token(user_id, email, role):
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")

# ==================== AUTH ENDPOINTS ====================

@app.route('/api/auth/login', methods=['GET', 'POST'])
def login():
    try:
        # Handle both GET and POST
        if request.method == 'GET':
            identifier = request.args.get('identifier')
            password = request.args.get('password')
            role = request.args.get('role')
        else:
            data = request.get_json()
            identifier = data.get('identifier')
            password = data.get('password')
            role = data.get('role')
        
        if not identifier or not password or not role:
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        
        # Determine which table to query based on role
        if role == 'admin':
            cur.execute("""
                SELECT admin_id, first_name, last_name, email, password, hospital 
                FROM admin 
                WHERE LOWER(email) = LOWER(%s)
            """, (identifier,))
        elif role == 'doctor':
            cur.execute("""
                SELECT doctor_id, first_name, last_name, email, password, department, 
                       specialization, qualification, experience 
                FROM doctor 
                WHERE LOWER(email) = LOWER(%s) OR doctor_id::text = %s
            """, (identifier, identifier))
        elif role == 'patient':
            cur.execute("""
                SELECT patient_id, first_name, last_name, email, password, phone, address 
                FROM patient 
                WHERE LOWER(email) = LOWER(%s) OR patient_id::text = %s
            """, (identifier, identifier))
        else:
            cur.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid role'}), 400
        
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if not user:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        # Verify password
        stored_password = user[4]
        if not bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        # Prepare user data based on role
        if role == 'admin':
            user_data = {
                'id': str(user[0]),
                'name': f"{user[1].title()} {user[2].title()}",
                'email': user[3],
                'role': role,
                'hospital': user[5] if len(user) > 5 else None
            }
        elif role == 'doctor':
            user_data = {
                'id': str(user[0]),
                'name': f"Dr. {user[1].title()} {user[2].title()}",
                'email': user[3],
                'role': role,
                'department': user[5] if len(user) > 5 else None,
                'specialization': user[6] if len(user) > 6 else None,
                'qualification': user[7] if len(user) > 7 else None,
                'experience': user[8] if len(user) > 8 else None
            }
        else:  # patient
            user_data = {
                'id': str(user[0]),
                'name': f"{user[1].title()} {user[2].title()}",
                'email': user[3],
                'role': role,
                'patientId': str(user[0]),
                'phone': user[5] if len(user) > 5 else None,
                'address': user[6] if len(user) > 6 else None
            }
        
        # Generate JWT token
        token = generate_token(user_data['id'], user_data['email'], role)
        
        return jsonify({
            'success': True,
            'user': user_data,
            'token': token
        }), 200
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Login failed'}), 500

@app.route('/api/auth/register', methods=['GET', 'POST'])
def register():
    try:
        # Handle both GET and POST
        if request.method == 'GET':
            name = request.args.get('name')
            email = request.args.get('email')
            password = request.args.get('password')
            phone = request.args.get('phone')
            address = request.args.get('address')
            role = request.args.get('role')
            hospital = request.args.get('hospital', 'default hospital')
        else:
            data = request.get_json()
            name = data.get('name')
            email = data.get('email')
            password = data.get('password')
            phone = data.get('phone')
            address = data.get('address')
            role = data.get('role')
            hospital = data.get('hospital', 'default hospital')
        
        # Validate required fields
        if not all([name, email, password, phone, address, role]):
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        # Parse name
        full_name = name.strip()
        name_parts = full_name.split()
        first_name = name_parts[0].lower()
        last_name = ' '.join(name_parts[1:]).lower() if len(name_parts) > 1 else ''
        
        email = email.lower()
        address = address.lower()
        
        # Only allow patient and admin registration
        if role not in ['patient', 'admin']:
            return jsonify({'success': False, 'error': 'Invalid role for registration'}), 400
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        password_str = hashed_password.decode('utf-8')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        
        try:
            if role == 'patient':
                # Generate patient ID
                cur.execute("SELECT COALESCE(MAX(patient_id), 1000000000) + 1 FROM patient")
                patient_id = cur.fetchone()[0]
                
                cur.execute("""
                    INSERT INTO patient (patient_id, first_name, last_name, phone, email, address, password)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (patient_id, first_name, last_name, phone, email, address, password_str))
                
                user_id = patient_id
                
            else:  # admin
                # Generate admin ID
                cur.execute("SELECT COALESCE(MAX(admin_id), 1000000000) + 1 FROM admin")
                admin_id = cur.fetchone()[0]
                
                cur.execute("""
                    INSERT INTO admin (admin_id, first_name, last_name, hospital, phone, email, address, password)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (admin_id, first_name, last_name, hospital.lower(), phone, email, address, password_str))
                
                user_id = admin_id
            
            conn.commit()
            
            # Generate token
            token = generate_token(str(user_id), email, role)
            
            user_data = {
                'id': str(user_id),
                'name': full_name.title(),
                'email': email,
                'role': role
            }
            
            cur.close()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Registration successful',
                'user': user_data,
                'token': token
            }), 201
            
        except psycopg2.errors.UniqueViolation as e:
            conn.rollback()
            cur.close()
            conn.close()
            
            if 'email' in str(e):
                return jsonify({'success': False, 'error': 'Email already exists'}), 409
            elif 'phone' in str(e):
                return jsonify({'success': False, 'error': 'Phone number already exists'}), 409
            else:
                return jsonify({'success': False, 'error': 'Registration failed - duplicate entry'}), 409
                
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            raise e
        
    except Exception as e:
        print(f"Registration error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Registration failed'}), 500

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        role = current_user['role']
        user_id = current_user['user_id']
        
        if role == 'admin':
            cur.execute("""
                SELECT admin_id, first_name, last_name, email, hospital, phone, address
                FROM admin WHERE admin_id = %s
            """, (user_id,))
        elif role == 'doctor':
            cur.execute("""
                SELECT doctor_id, first_name, last_name, email, department, 
                       specialization, qualification, experience, phone
                FROM doctor WHERE doctor_id = %s
            """, (user_id,))
        else:  # patient
            cur.execute("""
                SELECT patient_id, first_name, last_name, email, phone, address
                FROM patient WHERE patient_id = %s
            """, (user_id,))
        
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Format user data based on role
        if role == 'admin':
            user_data = {
                'id': str(user[0]),
                'name': f"{user[1].title()} {user[2].title()}",
                'email': user[3],
                'role': role,
                'hospital': user[4],
                'phone': user[5],
                'address': user[6]
            }
        elif role == 'doctor':
            user_data = {
                'id': str(user[0]),
                'name': f"Dr. {user[1].title()} {user[2].title()}",
                'email': user[3],
                'role': role,
                'department': user[4],
                'specialization': user[5],
                'qualification': user[6],
                'experience': user[7],
                'phone': user[8]
            }
        else:  # patient
            user_data = {
                'id': str(user[0]),
                'name': f"{user[1].title()} {user[2].title()}",
                'email': user[3],
                'role': role,
                'patientId': str(user[0]),
                'phone': user[4],
                'address': user[5]
            }
        
        return jsonify({'success': True, 'user': user_data}), 200
        
    except Exception as e:
        print(f"Get current user error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to fetch user data'}), 500

@app.route('/api/auth/change-password', methods=['GET', 'PUT'])
@token_required
def change_password(current_user):
    try:
        # Handle both GET and PUT
        if request.method == 'GET':
            current_password = request.args.get('currentPassword')
            new_password = request.args.get('newPassword')
        else:
            data = request.get_json()
            current_password = data.get('currentPassword')
            new_password = data.get('newPassword')
        
        if not current_password or not new_password:
            return jsonify({'success': False, 'error': 'Both passwords are required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        role = current_user['role']
        user_id = current_user['user_id']
        
        # Get current password from database
        if role == 'admin':
            cur.execute("SELECT password FROM admin WHERE admin_id = %s", (user_id,))
        elif role == 'doctor':
            cur.execute("SELECT password FROM doctor WHERE doctor_id = %s", (user_id,))
        else:
            cur.execute("SELECT password FROM patient WHERE patient_id = %s", (user_id,))
        
        result = cur.fetchone()
        if not result:
            cur.close()
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        stored_password = result[0]
        
        # Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), stored_password.encode('utf-8')):
            cur.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Current password is incorrect'}), 401
        
        # Hash new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        new_password_str = hashed_password.decode('utf-8')
        
        # Update password
        if role == 'admin':
            cur.execute("UPDATE admin SET password = %s WHERE admin_id = %s", 
                       (new_password_str, user_id))
        elif role == 'doctor':
            cur.execute("UPDATE doctor SET password = %s WHERE doctor_id = %s", 
                       (new_password_str, user_id))
        else:
            cur.execute("UPDATE patient SET password = %s WHERE patient_id = %s", 
                       (new_password_str, user_id))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        print(f"Change password error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to change password'}), 500

# ==================== DOCTOR ENDPOINTS ====================

@app.route('/api/doctors', methods=['GET'])
def get_doctors():
    try:
        admin_id = request.args.get('admin_id')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        
        if admin_id:
            cur.execute("""
                SELECT doctor_id, first_name, last_name, phone, email, department, 
                       experience, specialization, qualification
                FROM doctor WHERE admin_id = %s
            """, (admin_id,))
        else:
            cur.execute("""
                SELECT doctor_id, first_name, last_name, phone, email, department, 
                       experience, specialization, qualification
                FROM doctor
            """)
        
        doctors = cur.fetchall()
        cur.close()
        conn.close()
        
        doctors_list = []
        for doc in doctors:
            doctors_list.append({
                'id': str(doc[0]),
                'name': f"Dr. {doc[1].title()} {doc[2].title()}",
                'phone': doc[3],
                'email': doc[4],
                'department': doc[5],
                'experience': doc[6],
                'specialization': doc[7],
                'qualification': doc[8]
            })
        
        return jsonify({'success': True, 'doctors': doctors_list}), 200
        
    except Exception as e:
        print(f"Get doctors error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to fetch doctors'}), 500

@app.route('/api/doctor/add', methods=['GET', 'POST'])
def add_doctor():
    try:
        # Handle both GET and POST
        if request.method == 'GET':
            first_name = request.args.get('first_name')
            last_name = request.args.get('last_name')
            phone = request.args.get('phone')
            email = request.args.get('email')
            department = request.args.get('department')
            experience = request.args.get('experience')
            admin_id = request.args.get('admin_id')
            password = request.args.get('password', 'doctor123')
            specialization = request.args.get('specialization', '')
            qualification = request.args.get('qualification', '')
        else:
            data = request.get_json()
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            phone = data.get('phone')
            email = data.get('email')
            department = data.get('department')
            experience = data.get('experience')
            admin_id = data.get('admin_id')
            password = data.get('password', 'doctor123')
            specialization = data.get('specialization', '')
            qualification = data.get('qualification', '')
        
        # Validate
        if not all([first_name, last_name, phone, email, department, admin_id]):
            return jsonify({'success': False, 'error': 'Required fields missing'}), 400
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        password_str = hashed_password.decode('utf-8')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        
        # Generate doctor ID
        cur.execute("SELECT COALESCE(MAX(doctor_id), 2000000000) + 1 FROM doctor")
        doctor_id = cur.fetchone()[0]
        
        cur.execute("""
            INSERT INTO doctor (doctor_id, first_name, last_name, phone, email, 
                              department, experience, admin_id, password, specialization, qualification)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (doctor_id, first_name.lower(), last_name.lower(), phone, email.lower(),
              department.lower(), experience, admin_id, password_str, specialization, qualification))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Doctor added successfully', 'doctor_id': doctor_id}), 201
        
    except psycopg2.errors.UniqueViolation:
        return jsonify({'success': False, 'error': 'Email or phone already exists'}), 409
    except Exception as e:
        print(f"Add doctor error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to add doctor'}), 500

# ==================== PATIENT ENDPOINTS ====================

@app.route('/api/patients', methods=['GET'])
def get_patients():
    try:
        admin_id = request.args.get('admin_id')
        doctor_id = request.args.get('doctor_id')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        
        if admin_id:
            cur.execute("""
                SELECT patient_id, first_name, last_name, phone, email, address
                FROM patient WHERE admin_id = %s
            """, (admin_id,))
        elif doctor_id:
            cur.execute("""
                SELECT patient_id, first_name, last_name, phone, email, address
                FROM patient WHERE doctor_id = %s
            """, (doctor_id,))
        else:
            cur.execute("""
                SELECT patient_id, first_name, last_name, phone, email, address
                FROM patient
            """)
        
        patients = cur.fetchall()
        cur.close()
        conn.close()
        
        patients_list = []
        for pat in patients:
            patients_list.append({
                'id': str(pat[0]),
                'name': f"{pat[1].title()} {pat[2].title()}",
                'phone': pat[3],
                'email': pat[4],
                'address': pat[5]
            })
        
        return jsonify({'success': True, 'patients': patients_list}), 200
        
    except Exception as e:
        print(f"Get patients error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to fetch patients'}), 500

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'API is running'}), 200

# Test database connection
@app.route('/api/test-db', methods=['GET'])
def test_db():
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        cur.execute("SELECT version();")
        version = cur.fetchone()
        cur.close()
        conn.close()
        
        return jsonify({
            'success': True, 
            'message': 'Database connection successful',
            'version': version[0]
        }), 200
    except Exception as e:
        print(f"Database test error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')