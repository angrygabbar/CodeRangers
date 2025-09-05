# DecConnectHub/models.py

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import uuid

db = SQLAlchemy()

# Association table for the many-to-many relationship
candidate_contacts = db.Table('candidate_contacts',
    db.Column('candidate_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('developer_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class ProblemStatement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    users = db.relationship('User', foreign_keys='User.problem_statement_id', backref='assigned_problem', lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='candidate')
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    avatar_url = db.Column(db.String(200), nullable=False, default='https://api.dicebear.com/8.x/initials/svg?seed=User')
    
    problem_statement_id = db.Column(db.Integer, db.ForeignKey('problem_statement.id'), nullable=True)
    test_start_time = db.Column(db.DateTime, nullable=True)
    test_end_time = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    reminder_sent = db.Column(db.Boolean, default=False, nullable=False)
    test_completed = db.Column(db.Boolean, default=False, nullable=False) 

    moderator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    mobile_number = db.Column(db.String(20), nullable=True)
    primary_skill = db.Column(db.String(100), nullable=True)
    primary_skill_experience = db.Column(db.String(50), nullable=True)
    secondary_skill = db.Column(db.String(100), nullable=True)
    secondary_skill_experience = db.Column(db.String(50), nullable=True)
    resume_filename = db.Column(db.String(200), nullable=True)

    secret_question = db.Column(db.String(255), nullable=True)
    secret_answer_hash = db.Column(db.String(128), nullable=True)
    meeting_link = db.Column(db.String(255), nullable=True)

    allowed_contacts = db.relationship('User', secondary=candidate_contacts,
                                       primaryjoin=(candidate_contacts.c.candidate_id == id),
                                       secondaryjoin=(candidate_contacts.c.developer_id == id),
                                       backref=db.backref('contact_for', lazy='dynamic'), lazy='dynamic')

    created_problems = db.relationship('ProblemStatement', foreign_keys=[ProblemStatement.created_by_id], backref='creator', lazy=True)
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy=True)
    activity_updates = db.relationship('ActivityUpdate', backref='author', lazy=True)
    sent_snippets = db.relationship('CodeSnippet', foreign_keys='CodeSnippet.sender_id', backref='snippet_sender', lazy=True)
    received_snippets = db.relationship('CodeSnippet', foreign_keys='CodeSnippet.recipient_id', backref='snippet_recipient', lazy=True)
    applications = db.relationship('JobApplication', backref='candidate', lazy=True)
    test_submissions = db.relationship('CodeTestSubmission', foreign_keys='CodeTestSubmission.candidate_id', backref='candidate_submitter', lazy=True)
    received_tests = db.relationship('CodeTestSubmission', foreign_keys='CodeTestSubmission.recipient_id', backref='test_recipient', lazy=True)
    feedback_given = db.relationship('Feedback', foreign_keys='Feedback.moderator_id', backref='moderator', lazy=True)
    feedback_received = db.relationship('Feedback', foreign_keys='Feedback.candidate_id', backref='candidate', lazy=True)
    invoices = db.relationship('Invoice', backref='admin', lazy=True)


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
    language = db.Column(db.String(50), nullable=False, default='java')
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
    language = db.Column(db.String(50), nullable=False, default='java')
    submitted_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class AffiliateAd(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ad_name = db.Column(db.String(100), nullable=False, unique=True)
    affiliate_link = db.Column(db.Text, nullable=False)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    moderator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code_correctness = db.Column(db.Integer, nullable=False)
    code_efficiency = db.Column(db.Integer, nullable=False)
    code_readability = db.Column(db.Integer, nullable=False)
    problem_solving = db.Column(db.Integer, nullable=False)
    time_management = db.Column(db.Integer, nullable=False)
    remarks = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invoice_number = db.Column(db.String(50), unique=True, nullable=False)
    recipient_name = db.Column(db.String(100), nullable=False)
    recipient_email = db.Column(db.String(120), nullable=False)
    bill_to_address = db.Column(db.Text, nullable=True)
    ship_to_address = db.Column(db.Text, nullable=True)
    order_id = db.Column(db.String(50), nullable=True)
    subtotal = db.Column(db.Float, nullable=False)
    tax = db.Column(db.Float, nullable=False, default=0.0)
    total_amount = db.Column(db.Float, nullable=False)
    due_date = db.Column(db.Date, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    payment_details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    items = db.relationship('InvoiceItem', backref='invoice', lazy=True, cascade="all, delete-orphan")

class InvoiceItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    price = db.Column(db.Float, nullable=False)
    invoice_id = db.Column(db.Integer, db.ForeignKey('invoice.id'), nullable=False)

