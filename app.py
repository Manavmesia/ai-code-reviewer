from flask import Flask, redirect, render_template, request, url_for, flash, abort
from extensions import db, login_manager, bcrypt
from models import User, Assignment
from flask_login import login_required, logout_user, login_user, current_user
from decorators import role_required

app = Flask(__name__)

app.config["SECRET_KEY"] = "rbac-secret"
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "postgresql://postgres:Mam111%2A%23@localhost:5433/rbac_db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
login_manager.init_app(app)
bcrypt.init_app(app)


@app.route("/")
def role():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Invalid email or password")
            return render_template("login.html")

        if not bcrypt.check_password_hash(user.password_hash, password):
            flash("Invalid email or password")
            return render_template("login.html")

        login_user(user)

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Password do not match")
            return redirect(url_for("register"))

        existing_email = User.query.filter_by(email=email).first()

        if existing_email:
            flash("Email already exists")
            return redirect(url_for("register"))

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")

        user = User(name=name, email=email, password_hash=hashed, role="DEVELOPER")

        db.session.add(user)
        db.session.commit()

        flash(" Account created successfully. Please login.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "ADMIN":
        return render_template("dashboard.html")

    if current_user.role == "MANAGER":
        from sqlalchemy.orm import aliased

        Developer = aliased(User)

        devs = (
            db.session.query(Developer)
            .join(Assignment, Assignment.developer_id == Developer.id)
            .filter(Assignment.manager_id == current_user.id)
            .all()
        )

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

        existing = User.query.filter(
            User.email == email, User.id != current_user.id
        ).first()

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

            current_user.password_hash = bcrypt.generate_password_hash(password).decode(
                "utf-8"
            )

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
    role = request.args.get("role")
    sort = request.args.get("sort")
    specialization = request.args.get("specialization")

    query = User.query

    if role:
        query = query.filter(User.role == role)

    if specialization:
        query = query.filter(User.role_specialization == specialization)

    if sort == "name_asc":
        query = query.order_by(User.name.asc())
    elif sort == "name_desc":
        query = query.order_by(User.name.desc())
    elif sort == "date_asc":
        query = query.order_by(User.created_at.asc())
    elif sort == "date_desc":
        query = query.order_by(User.created_at.desc())

    users = query.all()
    return render_template(
        "admin_users.html",
        users=users,
        selected_role=role,
        selected_specialization=specialization,
    )


@app.route("/admin/create-user", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def create_user():
    assigned_ids = db.session.query(Assignment.developer_id).all()
    assigned_ids = [d[0] for d in assigned_ids]

    developers = User.query.filter(
        User.role == "DEVELOPER", ~User.id.in_(assigned_ids)
    ).all()

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]
        specialization = request.form["specialization"]

        existing = User.query.filter_by(email=email).first()

        if existing:
            flash("Email already exists")
            return render_template("create_user.html")

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")

        user = User(
            name=name,
            email=email,
            password_hash=hashed,
            role=role,
            role_specialization=specialization,
        )

        db.session.add(user)
        db.session.commit()

        if role == "MANAGER":
            dev_id = request.form.get("developer")

            if dev_id:
                assignment = Assignment(manager_id=user.id, developer_id=dev_id)
                db.session.add(assignment)
                db.session.commit()

        flash("User created successfully")
        return redirect(url_for("admin_users"))

    return render_template("create_user.html", developers=developers)


@app.route("/admin/assign", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def assign_dev():
    managers = User.query.filter_by(role="MANAGER").all()

    assigned_dev_ids = db.session.query(Assignment.developer_id)

    developers = User.query.filter(
        User.role == "DEVELOPER", ~User.id.in_(assigned_dev_ids)
    ).all()

    if request.method == "POST":
        manager_id = request.form["manager"]

        raw_ids = request.form.get("developers")
        if not raw_ids:
            flash("Please select at least one developer", "error")
            return redirect(url_for("assign_dev"))
        
        developer_ids = raw_ids.split(",")

        for dev_id in developer_ids:
            already = Assignment.query.filter_by(developer_id=dev_id).first()
            if not already:
                db.session.add(
                    Assignment(manager_id=manager_id, developer_id=dev_id)
                )

        db.session.commit()

        flash("Developer assigned successfully")
        return redirect(url_for("view_assignments"))

    return render_template("assign.html", managers=managers, developers=developers)


@app.route("/admin/assignments")
@login_required
@role_required("ADMIN")
def view_assignments():
    from sqlalchemy.orm import aliased

    Manager = aliased(User)
    Developer = aliased(User)

    assignments = (
        db.session.query(Assignment, Manager, Developer)
        .join(Manager, Assignment.manager_id == Manager.id)
        .join(Developer, Assignment.developer_id == Developer.id)
        .all()
    )

    return render_template("assignments.html", assignments=assignments)


@app.route("/admin/unassign/<assignment_id>")
@login_required
@role_required("ADMIN")
def unassign_dev(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)

    db.session.delete(assignment)
    db.session.commit()

    flash("Developer unassigned successfully")

    next_url = request.args.get("next")
    if next_url:
        return redirect(next_url)

    return redirect(url_for("view_assignments"))


@app.route("/admin/edit-user/<user_id>", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    developers = User.query.filter(User.role == "DEVELOPER").all()
    assigned_ids = {
        a.developer_id for a in Assignment.query.all()
    }
    my_assigned_ids = a.developer_id for a in Assignment.query.filter_by(manager_id = user.id).all()

    manager = None
    if user.role == "DEVELOPER":
        a = Assignment.query.filter_by(developer_id=user.id).first()
        if a:
            manager = User.query.get(a.manager_id)

    if request.method == "POST":
        user.name = request.form["name"]
        user.email = request.form["email"]
        user.role = request.form["role"]
        user.role_specialization = request.form["specialization"]

        if user.role == "MANAGER":
            new_dev_ids = request.form.getlist("developers")
            
            Assignment.query.filter_by(manager_id=user.id).delete()
            
            for dev_id in new_dev_ids:
                db.session.add(
                    Assignment(manager_id=user.id, developer_id=dev_id)
                )

        db.session.commit()
        flash("User updated successfully")
        return redirect(url_for("user_info", user_id=user.id))

    return render_template(
        "editor_user.html",
        user=user,
        developers = developers,
        assigned_ids = assigned_ids,
        manager=manager
    )


@app.route("/admin/user/<user_id>")
@login_required
@role_required("ADMIN")
def user_info(user_id):
    user = db.session.get(User, user_id)

    if not user:
        abort(404)

    assigned_devs = []
    if user.role == "MANAGER":
        assigned_devs = (
            db.session.query(User)
            .join(Assignment, Assignment.developer_id == User.id)
            .filter(Assignment.manager_id == user.id)
            .all()
        )

    manager = None
    if user.role == "DEVELOPER":
        manager = (
            db.session.query(User)
            .join(Assignment, Assignment.manager_id == User.id)
            .filter(Assignment.developer_id == user.id)
            .first()
        )

    return render_template(
        "user_info.html", user=user, assigned_devs=assigned_devs, manager=manager
    )


@app.route("/admin/assign-to-manager/<manager_id>/<developer_id>")
@login_required
@role_required("ADMIN")
def assign_to_manager(manager_id, developer_id):
    assignment = Assignment(manager_id=manager_id, developer_id=developer_id)

    db.session.add(assignment)
    db.session.commit()

    flash("Developer assigned successfully")
    return redirect(url_for("edit_user", user_id=manager_id))


@app.route("/admin/bulk-delete", methods=["POST"])
@login_required
@role_required("ADMIN")
def bulk_delete():
    user_ids = request.form.getlist("user_ids")

    if not user_ids:
        flash("No users selected", "error")
        return redirect(url_for("admin_users"))

    Assignment.query.filter(
        (Assignment.manager_id.in_(user_ids)) | (Assignment.developer_id.in_(user_ids))
    ).delete(synchronize_session=False)

    User.query.filter(User.id.in_(user_ids)).delete(synchronize_session=False)

    db.session.commit()

    flash(f"{len(user_ids)} users deleted successfully", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/delete-user/<user_id>", methods=["POST"])
@login_required
@role_required("ADMIN")
def delete_user(user_id):
    Assignment.query.filter(
        (Assignment.manager_id == user_id) | (Assignment.developer_id == user_id)
    ).delete(synchronize_session=False)

    user = User.query.get_or_404(user_id)

    db.session.delete(user)
    db.session.commit()

    flash("User deleted successfully", "success")
    return redirect(url_for("admin_users"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)