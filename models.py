from extensions import db
from flask_login import UserMixin
from sqlalchemy.dialects.postgresql import UUID
import uuid

class User(UserMixin, db.Model):
    __tablename__ = "users"
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(100))
    email = db.Column(db.String(150), unique=True)
    password_hash = db.Column(db.Text)
    role = db.Column(db.String(20))
    role_specialization = db.Column(db.String(50))
    
class Assignment(db.Model):
    __tablename__ = "assignments"
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    manager_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"))
    developer_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"))
