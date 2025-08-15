from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Message, ActivityUpdate, CodeSnippet, JobOpening, JobApplication
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devconnect.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_register'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/login-register', methods=['GET', 'POST'])
def login_register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if 'register' in request.form:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')

            if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
                flash('Username or email already exists.', 'danger')
                return redirect(url_for('login_register'))

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            avatar_url = f'https://api.dicebear.com/8.x/initials/svg?seed={username}'
            new_user = User(username=username, email=email, password_hash=hashed_password, role=role, avatar_url=avatar_url)
            
            if User.query.count() == 0:
                new_user.role = 'admin'
                new_user.is_approved = True

            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please wait for admin approval.', 'success')
            return redirect(url_for('login_register'))

        if 'login' in request.form:
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()

            if not user or not bcrypt.check_password_hash(user.password_hash, password):
                flash('Login failed. Please check your email and password.', 'danger')
                return redirect(url_for('login_register'))
            
            if not user.is_approved:
                flash('Your account has not been approved by an administrator yet.', 'warning')
                return redirect(url_for('login_register'))

            login_user(user, remember=True)
            return redirect(url_for('dashboard'))

    return render_template('login_register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'developer':
        return redirect(url_for('developer_dashboard'))
    else:
        return redirect(url_for('candidate_dashboard'))

@app.route('/admin')
@login_required
@role_required('admin')
def admin_dashboard():
    pending_users = User.query.filter_by(is_approved=False).all()
    all_users = User.query.all()
    messageable_users = User.query.filter(User.id != current_user.id).all() 
    received_snippets = CodeSnippet.query.filter_by(recipient_id=current_user.id).order_by(CodeSnippet.timestamp.desc()).all()
    applications = JobApplication.query.order_by(JobApplication.applied_at.desc()).all()
    # NEW: Fetch all activities for the admin to see
    activities = ActivityUpdate.query.order_by(ActivityUpdate.timestamp.desc()).all()
    return render_template('admin_dashboard.html', 
                           pending_users=pending_users, 
                           all_users=all_users, 
                           messageable_users=messageable_users,
                           received_snippets=received_snippets,
                           applications=applications,
                           activities=activities) # Pass activities to the template

@app.route('/developer', methods=['GET', 'POST'])
@login_required
@role_required('developer')
def developer_dashboard():
    if request.method == 'POST':
        content = request.form.get('activity_content')
        if content:
            new_activity = ActivityUpdate(content=content, author=current_user)
            db.session.add(new_activity)
            db.session.commit()
            flash('Activity posted!', 'success')
        return redirect(url_for('developer_dashboard'))
        
    activities = ActivityUpdate.query.order_by(ActivityUpdate.timestamp.desc()).all()
    other_users = User.query.filter(User.role != 'candidate', User.id != current_user.id).all()
    received_snippets = CodeSnippet.query.filter_by(recipient_id=current_user.id).order_by(CodeSnippet.timestamp.desc()).all()
    return render_template('developer_dashboard.html', 
                           activities=activities, 
                           other_users=other_users,
                           received_snippets=received_snippets)

@app.route('/candidate')
@login_required
@role_required('candidate')
def candidate_dashboard():
    messageable_users = User.query.filter(User.role.in_(['admin', 'developer'])).all()
    open_jobs = JobOpening.query.filter_by(is_open=True).order_by(JobOpening.created_at.desc()).all()
    my_applications = JobApplication.query.filter_by(user_id=current_user.id).all()
    applied_job_ids = [app.job_id for app in my_applications]
    return render_template('candidate_dashboard.html', 
                           messageable_users=messageable_users,
                           open_jobs=open_jobs,
                           my_applications=my_applications,
                           applied_job_ids=applied_job_ids)

@app.route('/approve_user/<int:user_id>')
@login_required
@role_required('admin')
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    db.session.commit()
    flash(f'User {user.username} has been approved.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    recipient_id = request.form.get('recipient_id')
    body = request.form.get('body')
    
    if not recipient_id or not body:
        flash('Message cannot be empty.', 'danger')
    else:
        msg = Message(sender_id=current_user.id, recipient_id=recipient_id, body=body)
        db.session.add(msg)
        db.session.commit()
        flash('Message sent!', 'success')
        
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/share_code', methods=['POST'])
@login_required
@role_required('candidate')
def share_code():
    recipient_id = request.form.get('recipient_id')
    java_code = request.form.get('java_code')
    if not recipient_id or not java_code.strip():
        flash('Please select a recipient and provide code.', 'danger')
    else:
        new_snippet = CodeSnippet(sender_id=current_user.id, recipient_id=recipient_id, code=java_code)
        db.session.add(new_snippet)
        db.session.commit()
        flash('Code snippet shared successfully!', 'success')
    return redirect(url_for('candidate_dashboard'))

@app.route('/post_job', methods=['POST'])
@login_required
@role_required('admin')
def post_job():
    title = request.form.get('job_title')
    description = request.form.get('job_description')
    if title and description:
        new_job = JobOpening(title=title, description=description)
        db.session.add(new_job)
        db.session.commit()
        flash('New job opening has been posted.', 'success')
    else:
        flash('Job title and description are required.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/apply_job/<int:job_id>')
@login_required
@role_required('candidate')
def apply_job(job_id):
    job = JobOpening.query.get_or_404(job_id)
    existing_application = JobApplication.query.filter_by(user_id=current_user.id, job_id=job.id).first()
    if existing_application:
        flash('You have already applied for this job.', 'warning')
    else:
        new_application = JobApplication(user_id=current_user.id, job_id=job.id)
        db.session.add(new_application)
        db.session.commit()
        flash('You have successfully applied for the job!', 'success')
    return redirect(url_for('candidate_dashboard'))

@app.route('/accept_application/<int:app_id>')
@login_required
@role_required('admin')
def accept_application(app_id):
    application = JobApplication.query.get_or_404(app_id)
    application.status = 'accepted'
    db.session.commit()
    flash(f"Application from {application.candidate.username} for '{application.job.title}' has been accepted.", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/reject_application/<int:app_id>')
@login_required
@role_required('admin')
def reject_application(app_id):
    application = JobApplication.query.get_or_404(app_id)
    application.status = 'rejected'
    db.session.commit()
    flash(f"Application from {application.candidate.username} for '{application.job.title}' has been rejected.", 'warning')
    return redirect(url_for('admin_dashboard'))

@app.context_processor
def inject_messages():
    if current_user.is_authenticated:
        messages = Message.query.filter(
            (Message.sender_id == current_user.id) | (Message.recipient_id == current_user.id)
        ).order_by(Message.timestamp.desc()).all()
        return dict(messages=messages)
    return dict(messages=[])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
