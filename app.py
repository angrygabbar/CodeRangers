# DecConnectHub/app.py

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Message, ActivityUpdate, CodeSnippet, JobOpening, JobApplication, CodeTestSubmission, ProblemStatement
from functools import wraps
import requests
import time
import os
from datetime import datetime, timedelta
from sqlalchemy import or_
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devconnect.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['UPLOAD_FOLDER'] = 'static/resumes'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_register'
login_manager.login_message_category = 'info'

RAPIDAPI_KEY = os.environ.get('RAPIDAPI_KEY', "0a6ba78971msh4c6e4bd030a7155p19e180jsnd30bdfc2386d")

# Predefined Secret Questions
SECRET_QUESTIONS = [
    "What was your first pet's name?",
    "What is your mother's maiden name?",
    "What was the name of your elementary school?",
    "In what city were you born?",
    "What is your favorite book?"
]

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)
    session.modified = True

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(roles):
    if not isinstance(roles, list):
        roles = [roles]
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

# (Home, Contact, Logout routes remain the same)
@app.route('/')
def home(): return render_template('home.html')
@app.route('/contact')
def contact(): return render_template('contact.html')
@app.route('/login-register', methods=['GET', 'POST'])
def login_register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        if 'register' in request.form:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')
            mobile_number = request.form.get('mobile_number')
            if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
                flash('Username or email already exists.', 'danger')
                return redirect(url_for('login_register'))
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            avatar_url = f'https://api.dicebear.com/8.x/initials/svg?seed={username}'
            new_user = User(username=username, email=email, password_hash=hashed_password, role=role, avatar_url=avatar_url, mobile_number=mobile_number)
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
            if not user.is_active:
                flash('Your account is blocked by admin. Kindly contact admin by raising a support ticket or connect via WhatsApp messaging.', 'danger')
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
    if current_user.role == 'admin': return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'developer': return redirect(url_for('developer_dashboard'))
    elif current_user.role == 'moderator': return redirect(url_for('moderator_dashboard'))
    else: return redirect(url_for('candidate_dashboard'))

@app.route('/messages')
@login_required
def messages():
    messageable_users_dict = {}
    now = datetime.utcnow()

    if current_user.role == 'candidate':
        # Candidates can message admins
        admins = User.query.filter_by(role='admin').all()
        for admin in admins:
            messageable_users_dict[admin.id] = admin

        # If a test is active, candidates can message their assigned moderator
        if current_user.test_start_time and current_user.test_end_time and current_user.test_start_time <= now <= current_user.test_end_time and current_user.moderator_id:
            moderator = User.query.get(current_user.moderator_id)
            if moderator:
                messageable_users_dict[moderator.id] = moderator

    elif current_user.role == 'moderator':
        # Moderators can message admins
        admins = User.query.filter_by(role='admin').all()
        for admin in admins:
            messageable_users_dict[admin.id] = admin

        # Moderators can message candidates they are assigned to, if the test is active
        assigned_candidates = User.query.filter_by(moderator_id=current_user.id).all()
        for candidate in assigned_candidates:
            if candidate.test_start_time and candidate.test_end_time and candidate.test_start_time <= now <= candidate.test_end_time:
                messageable_users_dict[candidate.id] = candidate

    else: # Admin and Developer
        messageable_users = User.query.filter(User.id != current_user.id).all()
        for user in messageable_users:
            messageable_users_dict[user.id] = user
            
    messageable_users = list(messageable_users_dict.values())
    return render_template('messages.html', messageable_users=messageable_users)

@app.route('/get_conversation/<int:other_user_id>')
@login_required
def get_conversation(other_user_id):
    messages = Message.query.filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.recipient_id == other_user_id),
            (Message.sender_id == other_user_id) & (Message.recipient_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()
    conversation = [
        {
            'sender_id': msg.sender_id,
            'body': msg.body,
            'timestamp': msg.timestamp.strftime('%b %d, %I:%M %p')
        } for msg in messages
    ]
    return jsonify(conversation)

@app.route('/manage_users')
@login_required
@role_required('admin')
def manage_users():
    users = User.query.order_by(User.id).all()
    return render_template('manage_users.html', users=users)

@app.route('/toggle_user_status/<int:user_id>')
@login_required
@role_required('admin')
def toggle_user_status(user_id):
    user_to_toggle = User.query.get_or_404(user_id)
    if user_to_toggle.id == current_user.id:
        flash('You cannot change your own status.', 'danger')
        return redirect(url_for('manage_users'))
    
    user_to_toggle.is_active = not user_to_toggle.is_active
    db.session.commit()
    status = "activated" if user_to_toggle.is_active else "deactivated"
    flash(f'User {user_to_toggle.username} has been {status}.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', secret_questions=SECRET_QUESTIONS)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    current_user.mobile_number = request.form.get('mobile_number')
    current_user.primary_skill = request.form.get('primary_skill')
    current_user.primary_skill_experience = request.form.get('primary_skill_experience')
    current_user.secondary_skill = request.form.get('secondary_skill')
    current_user.secondary_skill_experience = request.form.get('secondary_skill_experience')
    if 'resume' in request.files:
        file = request.files['resume']
        if file.filename != '':
            if file and file.filename.endswith('.pdf'):
                filename = secure_filename(f"{current_user.id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.resume_filename = filename
            else:
                flash('Only PDF files are allowed for resumes.', 'danger')
                return redirect(url_for('profile'))
    db.session.commit()
    flash('Your profile has been updated successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/update_security_question', methods=['POST'])
@login_required
def update_security_question():
    secret_question = request.form.get('secret_question')
    secret_answer = request.form.get('secret_answer')
    if secret_question and secret_answer:
        current_user.secret_question = secret_question
        current_user.secret_answer_hash = bcrypt.generate_password_hash(secret_answer).decode('utf-8')
        db.session.commit()
        flash('Your security question has been updated.', 'success')
    else:
        flash('Please select a question and provide an answer.', 'danger')
    return redirect(url_for('profile'))

@app.route('/view_profile/<int:user_id>')
@login_required
@role_required('admin')
def view_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view_user_profile.html', user=user)

@app.route('/edit_profile/<int:user_id>')
@login_required
@role_required('admin')
def edit_user_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('edit_user_profile.html', user=user)

@app.route('/update_user_profile/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def update_user_profile(user_id):
    user_to_update = User.query.get_or_404(user_id)
    
    user_to_update.mobile_number = request.form.get('mobile_number')
    user_to_update.primary_skill = request.form.get('primary_skill')
    user_to_update.primary_skill_experience = request.form.get('primary_skill_experience')
    user_to_update.secondary_skill = request.form.get('secondary_skill')
    user_to_update.secondary_skill_experience = request.form.get('secondary_skill_experience')

    if 'resume' in request.files:
        file = request.files['resume']
        if file.filename != '':
            if file and file.filename.endswith('.pdf'):
                filename = secure_filename(f"{user_to_update.id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user_to_update.resume_filename = filename
            else:
                flash('Only PDF files are allowed for resumes.', 'danger')
                return redirect(url_for('edit_user_profile', user_id=user_id))
    
    db.session.commit()
    flash(f'{user_to_update.username}\'s profile has been updated.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not bcrypt.check_password_hash(current_user.password_hash, old_password):
        flash('Old password is not correct.', 'danger')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('profile'))

    current_user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    db.session.commit()
    flash('Your password has been updated successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/admin/change_user_password/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def admin_change_user_password(user_id):
    user_to_update = User.query.get_or_404(user_id)
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('edit_user_profile', user_id=user_id))
    
    user_to_update.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    db.session.commit()
    flash(f'Password for {user_to_update.username} has been updated.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/admin')
@login_required
@role_required('admin')
def admin_dashboard():
    pending_users = User.query.filter_by(is_approved=False).all()
    received_snippets = CodeSnippet.query.filter_by(recipient_id=current_user.id).order_by(CodeSnippet.timestamp.desc()).all()
    applications = JobApplication.query.order_by(JobApplication.applied_at.desc()).all()
    activities = ActivityUpdate.query.order_by(ActivityUpdate.timestamp.desc()).all()
    candidates = User.query.filter_by(role='candidate').all()
    developers = User.query.filter_by(role='developer').all()
    moderators = User.query.filter_by(role='moderator').all()
    scheduled_candidates = User.query.filter(User.role == 'candidate', User.problem_statement_id != None).all()
    return render_template('admin_dashboard.html', 
                           pending_users=pending_users, 
                           received_snippets=received_snippets,
                           applications=applications, activities=activities,
                           candidates=candidates, developers=developers,
                           moderators=moderators, scheduled_candidates=scheduled_candidates)

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
    received_snippets = CodeSnippet.query.filter_by(recipient_id=current_user.id).order_by(CodeSnippet.timestamp.desc()).all()
    return render_template('developer_dashboard.html', 
                           activities=activities,
                           received_snippets=received_snippets)

@app.route('/moderator')
@login_required
@role_required('moderator')
def moderator_dashboard():
    scheduled_events = User.query.filter(User.problem_statement_id != None).all()
    
    ist_offset = timedelta(hours=5, minutes=30)
    for event in scheduled_events:
        if event.test_start_time:
            event.start_time_ist = (event.test_start_time + ist_offset).strftime('%b %d, %Y at %I:%M %p')
        if event.test_end_time:
            event.end_time_ist = (event.test_end_time + ist_offset).strftime('%b %d, %Y at %I:%M %p')

    return render_template('moderator_dashboard.html', scheduled_events=scheduled_events)

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

@app.route('/code_test')
@login_required
@role_required('candidate')
def code_test():
    now = datetime.utcnow()
    if not current_user.assigned_problem:
        message = "No test has been assigned to you yet."
        return render_template('test_locked.html', message=message)
    if current_user.test_start_time and now < current_user.test_start_time:
        ist_start_time = current_user.test_start_time + timedelta(hours=5, minutes=30)
        message = f"Your test has been assigned but is not yet active. It will be available starting {ist_start_time.strftime('%b %d, %Y at %I:%M %p')} IST."
        return render_template('test_locked.html', message=message)
    if current_user.test_end_time and now > current_user.test_end_time:
        ist_end_time = current_user.test_end_time + timedelta(hours=5, minutes=30)
        message = f"The deadline for your assigned test has passed. The test was available until {ist_end_time.strftime('%b %d, %Y at %I:%M %p')} IST."
        return render_template('test_locked.html', message=message)
    messageable_users = User.query.filter(User.role.in_(['admin', 'developer'])).all()
    return render_template('code_test.html', messageable_users=messageable_users)

# (All other existing routes remain the same)
# ...
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
    return redirect(url_for('messages'))
@app.route('/share_code', methods=['POST'])
@login_required
@role_required('candidate')
def share_code():
    recipient_id = request.form.get('recipient_id')
    code = request.form.get('code')
    language = "java"
    if not recipient_id or not code.strip():
        flash('Please select a recipient and provide code.', 'danger')
    else:
        new_snippet = CodeSnippet(sender_id=current_user.id, recipient_id=recipient_id, code=code, language=language)
        db.session.add(new_snippet)
        db.session.commit()
        flash('Code snippet shared successfully!', 'success')
    return redirect(url_for('candidate_dashboard'))

@app.route('/assign_moderator', methods=['POST'])
@login_required
@role_required('admin')
def assign_moderator():
    candidate_id = request.form.get('candidate_id')
    moderator_id = request.form.get('moderator_id')

    candidate = User.query.get(candidate_id)
    moderator = User.query.get(moderator_id)

    if candidate and moderator and candidate.role == 'candidate' and moderator.role == 'moderator':
        candidate.moderator_id = moderator_id
        db.session.commit()
        flash(f'Moderator {moderator.username} has been assigned to {candidate.username}.', 'success')
    else:
        flash('Invalid assignment.', 'danger')
    
    return redirect(url_for('admin_dashboard'))

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
@app.route('/submit_code_test', methods=['POST'])
@login_required
@role_required('candidate')
def submit_code_test():
    recipient_id = request.form.get('recipient_id')
    code = request.form.get('code')
    output = request.form.get('output')
    language = "java"
    if not recipient_id or not code.strip():
        flash('Please select a recipient and provide code.', 'danger')
    else:
        submission = CodeTestSubmission(
            candidate_id=current_user.id,
            recipient_id=recipient_id,
            code=code,
            output=output,
            language=language
        )
        db.session.add(submission)
        db.session.commit()
        flash('Your code test has been submitted successfully!', 'success')
    return redirect(url_for('code_test'))
@app.route('/run_code', methods=['POST'])
@login_required
def run_code():
    code = request.json.get('code')
    if not code:
        return jsonify({'error': 'No code provided'}), 400
    url = "https://online-java-compiler.p.rapidapi.com/compile"
    payload = code
    headers = {
        "content-type": "text/plain",
        "X-RapidAPI-Key": RAPIDAPI_KEY,
        "X-RapidAPI-Host": "online-java-compiler.p.rapidapi.com"
    }
    try:
        response = requests.post(url, data=payload.encode('utf-8'), headers=headers)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500
@app.route('/create_problem', methods=['POST'])
@login_required
@role_required(['admin', 'developer', 'moderator'])
def create_problem():
    title = request.form.get('problem_title')
    description = request.form.get('problem_description')
    if not title or not description:
        flash('Title and description are required.', 'danger')
    else:
        new_problem = ProblemStatement(title=title, description=description, created_by_id=current_user.id)
        db.session.add(new_problem)
        db.session.commit()
        flash('New problem statement created.', 'success')
    return redirect(url_for('events'))
@app.route('/assign_problem', methods=['POST'])
@login_required
@role_required(['admin', 'developer', 'moderator'])
def assign_problem():
    candidate_id = request.form.get('candidate_id')
    problem_id = request.form.get('problem_id')
    start_time_str = request.form.get('start_time')
    end_time_str = request.form.get('end_time')
    candidate = User.query.get(candidate_id)
    if not candidate or not problem_id or not start_time_str or not end_time_str:
        flash('Please select a candidate, a problem, and set both start and end times.', 'danger')
        return redirect(url_for('events'))
    try:
        start_time_ist = datetime.strptime(start_time_str, '%Y-%m-%dT%H:%M')
        end_time_ist = datetime.strptime(end_time_str, '%Y-%m-%dT%H:%M')
    except ValueError:
        flash('Invalid date/time format.', 'danger')
        return redirect(url_for('events'))
    ist_offset = timedelta(hours=5, minutes=30)
    start_time_utc = start_time_ist - ist_offset
    end_time_utc = end_time_ist - ist_offset
    candidate.problem_statement_id = problem_id
    candidate.test_start_time = start_time_utc
    candidate.test_end_time = end_time_utc
    db.session.commit()
    flash(f'Problem assigned to {candidate.username}.', 'success')
    return redirect(url_for('events'))
@app.route('/add_contact_for_candidate', methods=['POST'])
@login_required
@role_required('admin')
def add_contact_for_candidate():
    candidate_id = request.form.get('candidate_id')
    developer_id = request.form.get('developer_id')
    candidate = User.query.get(candidate_id)
    developer = User.query.get(developer_id)
    if candidate and developer and developer.role == 'developer':
        candidate.allowed_contacts.append(developer)
        db.session.commit()
        flash(f'Developer {developer.username} added to {candidate.username}\'s contacts.', 'success')
    else:
        flash('Invalid selection. Please try again.', 'danger')
    return redirect(url_for('admin_dashboard'))
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user and user.secret_question:
            return redirect(url_for('reset_with_question', user_id=user.id))
        else:
            flash('No account found with that email or no secret question is set.', 'warning')
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')
@app.route('/reset_with_question/<int:user_id>', methods=['GET', 'POST'])
def reset_with_question(user_id):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        answer = request.form.get('secret_answer')
        new_password = request.form.get('new_password')
        if user.secret_answer_hash and bcrypt.check_password_hash(user.secret_answer_hash, answer):
            user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            flash('Your password has been updated! You can now log in.', 'success')
            return redirect(url_for('login_register'))
        else:
            flash('Your secret answer was incorrect. Please try again.', 'danger')
            return redirect(url_for('reset_with_question', user_id=user.id))
    return render_template('reset_with_question.html', user=user)

@app.route('/events')
@login_required
@role_required(['admin', 'developer', 'moderator'])
def events():
    candidates = User.query.filter_by(role='candidate').all()
    problems = ProblemStatement.query.all()
    scheduled_events = User.query.filter(User.problem_statement_id != None).all()
    
    ist_offset = timedelta(hours=5, minutes=30)
    for event in scheduled_events:
        if event.test_start_time:
            event.start_time_ist = (event.test_start_time + ist_offset).strftime('%b %d, %Y at %I:%M %p')
        if event.test_end_time:
            event.end_time_ist = (event.test_end_time + ist_offset).strftime('%b %d, %Y at %I:%M %p')

    received_tests = CodeTestSubmission.query.order_by(CodeTestSubmission.submitted_at.desc()).all()

    return render_template('events.html', candidates=candidates, problems=problems, scheduled_events=scheduled_events, received_tests=received_tests)

@app.route('/reschedule_event/<int:user_id>', methods=['POST'])
@login_required
@role_required(['admin', 'developer', 'moderator'])
def reschedule_event(user_id):
    candidate = User.query.get_or_404(user_id)
    start_time_str = request.form.get('new_start_time')
    end_time_str = request.form.get('new_end_time')

    if not start_time_str or not end_time_str:
        flash('Please provide both a new start and end time.', 'danger')
        return redirect(request.referrer)
    
    try:
        start_time_ist = datetime.strptime(start_time_str, '%Y-%m-%dT%H:%M')
        end_time_ist = datetime.strptime(end_time_str, '%Y-%m-%dT%H:%M')
    except ValueError:
        flash('Invalid date/time format.', 'danger')
        return redirect(request.referrer)

    ist_offset = timedelta(hours=5, minutes=30)
    candidate.test_start_time = start_time_ist - ist_offset
    candidate.test_end_time = end_time_ist - ist_offset
    db.session.commit()
    flash(f'Event for {candidate.username} has been rescheduled.', 'success')
    
    if current_user.role == 'moderator':
        return redirect(url_for('moderator_dashboard'))
    else:
        return redirect(url_for('events'))

@app.route('/cancel_event/<int:user_id>')
@login_required
@role_required(['admin', 'developer', 'moderator'])
def cancel_event(user_id):
    candidate = User.query.get_or_404(user_id)
    candidate.problem_statement_id = None
    candidate.test_start_time = None
    candidate.test_end_time = None
    db.session.commit()
    flash(f'Event for {candidate.username} has been canceled.', 'success')
    
    if current_user.role == 'moderator':
        return redirect(url_for('moderator_dashboard'))
    else:
        return redirect(url_for('events'))


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