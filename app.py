from flask import Flask, redirect, render_template, request, url_for, flash
from extensions import db, login_manager, bcrypt
from models import User, Assignment
from flask_login import login_required, logout_user, login_user, current_user
from decorators import role_required

app = Flask(__name__)

app.config["SECRET_KEY"] = "rbac-secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:Mam111%2A%23@localhost:5433/rbac_db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
login_manager.init_app(app)
bcrypt.init_app(app)

@app.route("/")
def role():
    return render_template("roles.html")

@app.route("/login/<role>", methods=["GET", "POST"])
def login(role):
    role = role.upper()
    
    if role not in ["ADMIN", "MANAGER", "DEVELOPER"]:
        return "invalid role", 404
    
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        
        user = User.query.filter_by(email = email).first()
        
        if not user:
            flash("Invalid email or password")
            return render_template("login.html", role = role)
        
        if not bcrypt.check_password_hash(user.password_hash, password):
            flash("Invalid email or password")
            return render_template("login.html", role = role)
        
        if user.role != role:
            flash("You are not authorized to login as this role")
            return render_template("login.html", role=role)
        
        login_user(user)
        
        return redirect(url_for("dashboard"))
    
    return render_template("login.html", role=role)


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)

@app.route("/register-admin", methods=["GET", "POST"])
def register_admin():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        
        if password != confirm_password:
            flash("Password do not match")
            return render_template("register_admin.html")
        
        existing_email = User.query.filter_by(email = email).first()
        
        if existing_email:
            flash("Email already exists")
            return render_template("register_admin.html")
        
        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        
        admin = User(
            name = name,
            email = email,
            password_hash = hashed,
            role = "ADMIN")
        
        db.session.add(admin)
        db.session.commit()
        
        flash("Admin registered successfully. Please login.")
        return redirect(url_for("login", role="admin"))
        
    return render_template("register_admin.html")

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "ADMIN":
        return render_template("dashboard.html")

    if current_user.role == "MANAGER":
        from sqlalchemy.orm import aliased
        Developer = aliased(User)

        devs = db.session.query(Developer) \
            .join(Assignment, Assignment.developer_id == Developer.id) \
            .filter(Assignment.manager_id == current_user.id) \
            .all()
            
        return render_template("manager_dashboard.html", devs=devs)
    
    if current_user.role == "DEVELOPER":
        return render_template("developer_dashboard.html")

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        
        existing = User.query.filter(User.email == email, User.id != current_user.id).first()
        
        if existing:
            flash("Email already in use")
            return redirect(url_for("settings"))
        
        current_user.name = name
        current_user.email = email
        
        if password:
            if password != confirm:
                flash("Passwords do not match")
                return redirect(url_for("settings"))
            
            if bcrypt.check_password_hash(current_user.password_hash, password):
                flash("New password must be different from current password")
                return redirect(url_for("settings"))

            current_user.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        
        db.session.commit()
        
        flash("Profile updated")
        return redirect(url_for("settings"))
        
    return render_template("settings.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")

@app.route("/admin/users")
@login_required
@role_required("ADMIN")
def admin_users():
    users = User.query.all()
    return render_template("admin_users.html", users=users)

@app.route("/admin/create-user", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def create_user():
    assigned_ids = db.session.query(Assignment.developer_id).all()
    assigned_ids = [d[0] for d in assigned_ids]
    
    developers = User.query.filter(
        User.role == "DEVELOPER",
        ~User.id.in_(assigned_ids)
    ).all()
        
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]
        specialization = request.form["specialization"]
        
        existing = User.query.filter_by(email = email).first()

        if existing:
            flash("Email already exists")
            return render_template("create_user.html")
        
        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        
        user = User(
            name = name,
            email = email,
            password_hash = hashed,
            role = role,
            role_specialization = specialization

        )
        
        db.session.add(user)
        db.session.commit()
        
        if role == "MANAGER":
            dev_id = request.form.get("developer")
            
            if dev_id:
                assignment = Assignment(manager_id = user.id, developer_id = dev_id)
                db.session.add(assignment)
                db.session.commit()
        
        flash("User created successfully")
        return redirect(url_for("admin_users"))
    
    return render_template("create_user.html", developers = developers)

@app.route("/admin/assign", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def assign_dev():
    managers = User.query.filter_by(role = "MANAGER").all()
    developers = User.query.filter_by(role = "DEVELOPER").all()
    
    if request.method == "POST":
        manager_id = request.form["manager"]
        developer_id = request.form["developer"]
        
        existing = Assignment.query.filter_by(developer_id = developer_id).first()
        
        if existing:
            flash("Developer already assigned to a manager")
            return redirect(url_for("assign_dev"))
        
        assignment = Assignment(manager_id = manager_id, developer_id = developer_id)
        
        db.session.add(assignment)
        db.session.commit()
        
        flash("Developer assigned successfully")
        return redirect(url_for("assign_dev"))
    
    return render_template("assign.html", managers = managers, developers = developers)

@app.route("/admin/assignments")
@login_required
@role_required("ADMIN")
def view_assignments():
    from sqlalchemy.orm import aliased

    Manager = aliased(User)
    Developer = aliased(User)
    
    assignments = db.session.query(Assignment, Manager, Developer) \
        .join(Manager, Assignment.manager_id == Manager.id) \
        .join(Developer, Assignment.developer_id == Developer.id) \
        .all()
        
    return render_template("assignments.html", assignments = assignments)

@app.route("/admin/unassign/<assignment_id>")
@login_required
@role_required("ADMIN")
def unassign_dev(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)
    
    db.session.delete(assignment)
    db.session.commit()
    
    flash("Developer unassigned successfully")
    return redirect(url_for("view_assignments"))
        
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)