
import os
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

from flask_sqlalchemy import SQLAlchemy

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

from sqlalchemy import or_


# =====================================================
# FLASK APPLICATION
# =====================================================

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")


# =====================================================
# PROJECT DIRECTORIES
# =====================================================

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        ".."
    )
)

DATABASE_DIR = os.path.join(
    BASE_DIR,
    "database"
)

os.makedirs(
    DATABASE_DIR,
    exist_ok=True
)


UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "frontend",
    "static",
    "uploads"
)

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# =====================================================
# DATABASE CONFIGURATION
# =====================================================

DATABASE_PATH = os.path.join(
    DATABASE_DIR,
    "incidents.db"
)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + DATABASE_PATH
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


ALLOWED_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp"
}


db = SQLAlchemy(app)


# =====================================================
# LOGIN MANAGER
# =====================================================

login_manager = LoginManager(app)

login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):

    return User.query.get(
        int(user_id)
    )


# =====================================================
# USER MODEL
# =====================================================

class User(
    UserMixin,
    db.Model
):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default="user"
    )

    incidents = db.relationship(
        "Incident",
        backref="reporter",
        lazy=True
    )


# =====================================================
# INCIDENT MODEL
# =====================================================

class Incident(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(200),
        nullable=False
    )

    incident_type = db.Column(
        db.String(100),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        nullable=False
    )

    status = db.Column(
        db.String(30),
        default="Reported"
    )

    affected_system = db.Column(
        db.String(200)
    )

    evidence_image = db.Column(
        db.String(255)
    )

    assigned_to = db.Column(
        db.String(100)
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    reported_by = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    responses = db.relationship(
        "Response",
        backref="incident",
        lazy=True,
        cascade="all, delete-orphan"
    )


# =====================================================
# RESPONSE MODEL
# =====================================================

class Response(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    action_taken = db.Column(
        db.Text,
        nullable=False
    )

    responder = db.Column(
        db.String(100),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    incident_id = db.Column(
        db.Integer,
        db.ForeignKey("incident.id"),
        nullable=False
    )


# =====================================================
# HELPER FUNCTION
# =====================================================

def allowed_file(filename):

    return (
        "." in filename
        and
        filename.rsplit(
            ".",
            1
        )[1].lower()
        in ALLOWED_EXTENSIONS
    )


# =====================================================
# HOME
# =====================================================

@app.route("/")
def home():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# =====================================================
# REGISTER
# =====================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not name or not email or not password:

            flash(
                "All fields are required.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:

            flash(
                "Email already registered.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        # Existing database already contains users,
        # so newly registered users become normal users.
        if User.query.count() == 0:

            role = "admin"

        else:

            role = "user"

        user = User(
            name=name,
            email=email,
            password=generate_password_hash(password),
            role=role
        )

        db.session.add(user)

        db.session.commit()

        flash(
            "Registration successful! Please login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# =====================================================
# LOGIN
# =====================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        user = User.query.filter_by(
            email=email
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            login_user(user)

            flash(
                "Login successful!",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid email or password.",
            "danger"
        )

    return render_template(
        "login.html"
    )


# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(
        url_for("login")
    )


# =====================================================
# DASHBOARD
# =====================================================

@app.route("/dashboard")
@login_required
def dashboard():

    if current_user.role == "admin":

        incident_list = Incident.query.order_by(
            Incident.created_at.desc()
        ).all()

    else:

        incident_list = Incident.query.filter_by(
            reported_by=current_user.id
        ).order_by(
            Incident.created_at.desc()
        ).all()

    total = len(
        incident_list
    )

    critical = sum(
        1
        for incident in incident_list
        if incident.severity == "Critical"
    )

    high = sum(
        1
        for incident in incident_list
        if incident.severity == "High"
    )

    investigating = sum(
        1
        for incident in incident_list
        if incident.status == "Investigating"
    )

    resolved = sum(
        1
        for incident in incident_list
        if incident.status == "Resolved"
    )

    return render_template(
        "dashboard.html",
        incidents=incident_list[:5],
        total=total,
        critical=critical,
        high=high,
        investigating=investigating,
        resolved=resolved
    )


# =====================================================
# REPORT INCIDENT
# =====================================================

@app.route(
    "/report",
    methods=["GET", "POST"]
)
@login_required
def report_incident():

    if request.method == "POST":

        title = request.form.get(
            "title",
            ""
        ).strip()

        incident_type = request.form.get(
            "incident_type",
            ""
        )

        description = request.form.get(
            "description",
            ""
        ).strip()

        severity = request.form.get(
            "severity",
            ""
        )

        affected_system = request.form.get(
            "affected_system",
            ""
        ).strip()

        image = request.files.get(
            "evidence_image"
        )

        image_filename = None

        if image and image.filename:

            if not allowed_file(
                image.filename
            ):

                flash(
                    "Only PNG, JPG, JPEG, GIF and WEBP images are allowed.",
                    "danger"
                )

                return redirect(
                    url_for("report_incident")
                )

            original_filename = secure_filename(
                image.filename
            )

            timestamp = datetime.now().strftime(
                "%Y%m%d%H%M%S%f"
            )

            image_filename = (
                timestamp
                + "_"
                + original_filename
            )

            image_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                image_filename
            )

            image.save(
                image_path
            )

        if not title or not description:

            flash(
                "Title and description are required.",
                "danger"
            )

            return redirect(
                url_for("report_incident")
            )

        incident = Incident(
            title=title,
            incident_type=incident_type,
            description=description,
            severity=severity,
            affected_system=affected_system,
            evidence_image=image_filename,
            status="Reported",
            reported_by=current_user.id
        )

        db.session.add(
            incident
        )

        db.session.commit()

        flash(
            "Incident reported successfully!",
            "success"
        )

        return redirect(
            url_for("incidents")
        )

    return render_template(
        "report.html"
    )


# =====================================================
# INCIDENT LIST
# =====================================================

@app.route("/incidents")
@login_required
def incidents():

    search = request.args.get(
        "search",
        ""
    ).strip()

    severity = request.args.get(
        "severity",
        ""
    )

    status = request.args.get(
        "status",
        ""
    )

    if current_user.role == "admin":

        query = Incident.query

    else:

        query = Incident.query.filter_by(
            reported_by=current_user.id
        )

    if search:

        query = query.filter(

            or_(

                Incident.title.ilike(
                    f"%{search}%"
                ),

                Incident.incident_type.ilike(
                    f"%{search}%"
                ),

                Incident.description.ilike(
                    f"%{search}%"
                )

            )

        )

    if severity:

        query = query.filter_by(
            severity=severity
        )

    if status:

        query = query.filter_by(
            status=status
        )

    incident_list = query.order_by(
        Incident.created_at.desc()
    ).all()

    return render_template(
        "incidents.html",
        incidents=incident_list,
        search=search,
        selected_severity=severity,
        selected_status=status
    )


# =====================================================
# INCIDENT DETAILS
# =====================================================

@app.route(
    "/incident/<int:incident_id>"
)
@login_required
def incident_detail(
    incident_id
):

    incident = Incident.query.get_or_404(
        incident_id
    )

    if (
        current_user.role != "admin"
        and
        incident.reported_by != current_user.id
    ):

        flash(
            "You are not authorized to view this incident.",
            "danger"
        )

        return redirect(
            url_for("incidents")
        )

    # =================================================
    # GET ALL ANALYST USERS
    # =================================================

    analysts = User.query.filter_by(
        role="analyst"
    ).order_by(
        User.name
    ).all()

    return render_template(
        "incident_detail.html",
        incident=incident,
        analysts=analysts
    )


# =====================================================
# UPDATE INCIDENT
# =====================================================

@app.route(
    "/incident/<int:incident_id>/update",
    methods=["POST"]
)
@login_required
def update_incident(
    incident_id
):

    if current_user.role != "admin":

        flash(
            "Only administrators can update incidents.",
            "danger"
        )

        return redirect(
            url_for(
                "incident_detail",
                incident_id=incident_id
            )
        )

    incident = Incident.query.get_or_404(
        incident_id
    )

    incident.status = request.form.get(
        "status"
    )

    incident.severity = request.form.get(
        "severity"
    )

    incident.assigned_to = request.form.get(
        "assigned_to",
        ""
    ).strip()

    incident.updated_at = datetime.utcnow()

    db.session.commit()

    flash(
        "Incident updated successfully!",
        "success"
    )

    return redirect(
        url_for(
            "incident_detail",
            incident_id=incident_id
        )
    )


# =====================================================
# ADD RESPONSE
# =====================================================

@app.route(
    "/incident/<int:incident_id>/response",
    methods=["POST"]
)
@login_required
def add_response(
    incident_id
):

    incident = Incident.query.get_or_404(
        incident_id
    )

    if (
        current_user.role != "admin"
        and
        incident.reported_by != current_user.id
    ):

        flash(
            "You are not authorized.",
            "danger"
        )

        return redirect(
            url_for(
                "incident_detail",
                incident_id=incident_id
            )
        )

    action_taken = request.form.get(
        "action_taken",
        ""
    ).strip()

    if not action_taken:

        flash(
            "Response action cannot be empty.",
            "danger"
        )

        return redirect(
            url_for(
                "incident_detail",
                incident_id=incident_id
            )
        )

    response = Response(
        action_taken=action_taken,
        responder=current_user.name,
        incident_id=incident.id
    )

    db.session.add(
        response
    )

    db.session.commit()

    flash(
        "Response action added successfully!",
        "success"
    )

    return redirect(
        url_for(
            "incident_detail",
            incident_id=incident_id
        )
    )


# =====================================================
# DATABASE CREATION
# =====================================================

with app.app_context():

    db.create_all()


# =====================================================
# START SERVER
# =====================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )

