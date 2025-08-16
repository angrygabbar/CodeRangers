from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import uuid

db = SQLAlchemy()

# NEW: ProblemStatement Model
class ProblemStatement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # FIX: Explicitly define the foreign key for the 'users' relationship
    users = db.relationship('User', foreign_keys='User.problem_statement_id', backref='assigned_problem', lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='candidate')
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    avatar_url = db.Column(db.String(200), nullable=False, default='https://api.dicebear.com/8.x/initials/svg?seed=User')
    
    # This is the foreign key that links a User to their assigned problem
    problem_statement_id = db.Column(db.Integer, db.ForeignKey('problem_statement.id'), nullable=True)

    # NEW: Add a relationship to easily find the creator of a problem
    created_problems = db.relationship('ProblemStatement', foreign_keys=[ProblemStatement.created_by_id], backref='creator', lazy=True)

    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy=True)
    activity_updates = db.relationship('ActivityUpdate', backref='author', lazy=True)
    sent_snippets = db.relationship('CodeSnippet', foreign_keys='CodeSnippet.sender_id', backref='snippet_sender', lazy=True)
    received_snippets = db.relationship('CodeSnippet', foreign_keys='CodeSnippet.recipient_id', backref='snippet_recipient', lazy=True)
    applications = db.relationship('JobApplication', backref='candidate', lazy=True)
    test_submissions = db.relationship('CodeTestSubmission', foreign_keys='CodeTestSubmission.candidate_id', backref='candidate_submitter', lazy=True)
    received_tests = db.relationship('CodeTestSubmission', foreign_keys='CodeTestSubmission.recipient_id', backref='test_recipient', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class ActivityUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class CodeSnippet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class JobOpening(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    is_open = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    applications = db.relationship('JobApplication', backref='job', lazy=True)

class JobApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey('job_opening.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)
    applied_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class CodeTestSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)
    output = db.Column(db.Text, nullable=True)
    submitted_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
