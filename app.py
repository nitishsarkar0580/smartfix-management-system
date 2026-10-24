from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os
import hashlib
import json
import urllib.request
import urllib.error

from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "local-development-only-change-me"
)

DATABASE = os.environ.get("DATABASE_PATH", "smartfix.db")


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ==================================================
# PASSWORD SECURITY
# ==================================================

def password_matches(stored, provided):
    if stored.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored, provided)

    return stored == provided


# ==================================================
# PASSWORD RESET TOKEN
# ==================================================

def reset_serializer():
    return URLSafeTimedSerializer(
        app.secret_key,
        salt="smartfix-customer-reset-v1"
    )


# ==================================================
# BREVO EMAIL API
# ==================================================

def send_reset_email(recipient, link):

    api_key = os.environ.get("BREVO_API_KEY")

    sender = (
        os.environ.get("BREVO_SENDER_EMAIL")
        or os.environ.get("SMTP_EMAIL")
    )

    if not api_key or not sender:
        raise RuntimeError("Brevo email settings missing")

    url = "https://api.brevo.com/v3/smtp/email"

    payload = {
        "sender": {
            "name": "SmartFix Support",
            "email": sender
        },
        "to": [
            {
                "email": recipient
            }
        ],
        "subject": "SmartFix Password Reset",
        "textContent": (
            "Hello,\n\n"
            "You requested a password reset for your SmartFix account.\n\n"
            "Click the link below:\n\n"
            + link +
            "\n\nThis link expires in 15 minutes.\n\n"
            "If you did not request this, ignore this email.\n\n"
            "SmartFix Support"
        )
    }

    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "accept": "application/json",
            "api-key": api_key,
            "content-type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            response.read()

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        app.logger.error(
            "Brevo API error: HTTP %s - %s",
            e.code,
            error_body[:500]
        )
        raise RuntimeError("Brevo API request failed") from e


# ==================================================
# CREATE CUSTOMER TABLE
# ==================================================

def create_database():

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            mobile TEXT NOT NULL,
            password TEXT NOT NULL,
            address TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ==================================================
# CREATE REPAIR TABLE
# ==================================================

def create_repair_table():

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS repair_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_name TEXT NOT NULL,
            mobile TEXT NOT NULL,
            service_type TEXT NOT NULL,
            description TEXT NOT NULL,
            address TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            technician_id INTEGER
        )
    """)

    columns = conn.execute(
        "PRAGMA table_info(repair_requests)"
    ).fetchall()

    if "technician_id" not in [c["name"] for c in columns]:

        conn.execute(
            "ALTER TABLE repair_requests ADD COLUMN technician_id INTEGER"
        )

    conn.commit()
    conn.close()


# ==================================================
# CREATE ADMIN TABLE
# ==================================================

def create_admin_table():

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    admin = conn.execute(
        "SELECT * FROM admins WHERE username = ?",
        ("admin",)
    ).fetchone()

    if admin is None:

        conn.execute(
            "INSERT INTO admins (username, password) VALUES (?, ?)",
            ("admin", "admin123")
        )

    conn.commit()
    conn.close()


# ==================================================
# CREATE TECHNICIAN TABLE
# ==================================================

def create_technician_table():

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS technicians (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            mobile TEXT NOT NULL,
            specialization TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/services")
def services():
    return render_template("services.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


# ==================================================
# CUSTOMER REGISTRATION
# ==================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form["name"]
        email = request.form["email"].strip().lower()
        mobile = request.form["mobile"]
        password = request.form["password"]
        address = request.form["address"]

        conn = get_db_connection()

        try:

            conn.execute("""
                INSERT INTO customers
                (name, email, mobile, password, address)
                VALUES (?, ?, ?, ?, ?)
            """, (
                name,
                email,
                mobile,
                generate_password_hash(password),
                address
            ))

            conn.commit()

        except sqlite3.IntegrityError:

            conn.close()

            return "Email already registered."

        conn.close()

        return redirect("/login")

    return render_template("register.html")


# ==================================================
# CUSTOMER LOGIN
# ==================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db_connection()

        customer = conn.execute(
            "SELECT * FROM customers WHERE lower(email) = ?",
            (email,)
        ).fetchone()

        if customer and password_matches(
            customer["password"],
            password
        ):

            if not customer["password"].startswith(
                ("scrypt:", "pbkdf2:")
            ):

                conn.execute(
                    "UPDATE customers SET password = ? WHERE id = ?",
                    (
                        generate_password_hash(password),
                        customer["id"]
                    )
                )

                conn.commit()

            conn.close()

            session["customer_id"] = customer["id"]
            session["customer_name"] = customer["name"]

            return redirect("/dashboard")

        conn.close()

        return "Invalid email or password."

    return render_template("login.html")


# ==================================================
# FORGOT PASSWORD
# ==================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        conn = get_db_connection()

        customer = conn.execute(
            "SELECT id, email, password FROM customers "
            "WHERE lower(email) = ?",
            (email,)
        ).fetchone()

        conn.close()

        if customer:

            fingerprint = hashlib.sha256(
                customer["password"].encode()
            ).hexdigest()

            token = reset_serializer().dumps({
                "id": customer["id"],
                "fp": fingerprint
            })

            link = url_for(
                "reset_password",
                token=token,
                _external=True
            )

            try:

                send_reset_email(
                    customer["email"],
                    link
                )

            except (OSError, RuntimeError):

                app.logger.exception(
                    "Could not send password reset email"
                )

                return (
                    "Email service is temporarily unavailable. "
                    "Please try again later.",
                    503
                )

        return (
            "If this email is registered, a password reset "
            "link has been sent. Check your inbox."
        )

    return render_template("forgot_password.html")


# ==================================================
# RESET PASSWORD
# ==================================================

@app.route(
    "/reset-password/<token>",
    methods=["GET", "POST"]
)
def reset_password(token):

    try:

        data = reset_serializer().loads(
            token,
            max_age=900
        )

    except (BadSignature, SignatureExpired):

        return (
            "This reset link is invalid or expired. "
            "Request a new one.",
            400
        )

    conn = get_db_connection()

    customer = conn.execute(
        "SELECT id, password FROM customers WHERE id = ?",
        (data.get("id"),)
    ).fetchone()

    if (
        not customer
        or hashlib.sha256(
            customer["password"].encode()
        ).hexdigest() != data.get("fp")
    ):

        conn.close()

        return (
            "This reset link is invalid or has already been used.",
            400
        )

    if request.method == "POST":

        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(password) < 8 or password != confirm:

            conn.close()

            return (
                "Passwords must match and contain "
                "at least 8 characters.",
                400
            )

        conn.execute(
            "UPDATE customers SET password = ? WHERE id = ?",
            (
                generate_password_hash(password),
                customer["id"]
            )
        )

        conn.commit()
        conn.close()

        return redirect(url_for("login"))

    conn.close()

    return render_template("reset_password.html")


# ==================================================
# CUSTOMER DASHBOARD
# ==================================================

@app.route("/dashboard")
def dashboard():

    if "customer_id" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        name=session["customer_name"]
    )


# ==================================================
# REPAIR REQUEST
# ==================================================

@app.route(
    "/repair-request",
    methods=["GET", "POST"]
)
def repair_request():

    if "customer_id" not in session:
        return redirect("/login")

    if request.method == "POST":

        mobile = request.form["mobile"]
        service_type = request.form["service_type"]
        description = request.form["description"]
        address = request.form["address"]

        conn = get_db_connection()

        conn.execute("""
            INSERT INTO repair_requests
            (customer_name, mobile, service_type,
             description, address, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            session["customer_name"],
            mobile,
            service_type,
            description,
            address,
            "Pending"
        ))

        conn.commit()
        conn.close()

        return redirect("/my-requests")

    return render_template("repair_request.html")


# ==================================================
# MY REQUESTS
# ==================================================

@app.route("/my-requests")
def my_requests():

    if "customer_id" not in session:
        return redirect("/login")

    conn = get_db_connection()

    requests_data = conn.execute("""
        SELECT repair_requests.*,
               technicians.name AS technician_name
        FROM repair_requests
        LEFT JOIN technicians
        ON repair_requests.technician_id = technicians.id
        WHERE repair_requests.customer_name = ?
        ORDER BY repair_requests.id DESC
    """, (
        session["customer_name"],
    )).fetchall()

    conn.close()

    return render_template(
        "my_requests.html",
        requests=requests_data
    )


# ==================================================
# CUSTOMER LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.pop("customer_id", None)
    session.pop("customer_name", None)

    return redirect("/")


# ==================================================
# ADMIN LOGIN
# ==================================================

@app.route(
    "/admin-login",
    methods=["GET", "POST"]
)
def admin_login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()

        admin = conn.execute("""
            SELECT * FROM admins
            WHERE username = ?
        """, (username,)).fetchone()

        conn.close()

        if admin and password_matches(
            admin["password"],
            password
        ):

            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]

            return redirect("/admin")

        return "Invalid admin username or password."

    return render_template("admin_login.html")


# ==================================================
# ADMIN FORGOT PASSWORD (BREVO)
# ==================================================

@app.route("/admin-forgot-password", methods=["GET", "POST"])
def admin_forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        recovery_email = os.environ.get("ADMIN_RECOVERY_EMAIL", "").strip().lower()

        if recovery_email and email == recovery_email:
            conn = get_db_connection()
            admin = conn.execute(
                "SELECT id, username, password FROM admins WHERE username = ?",
                ("admin",)
            ).fetchone()
            conn.close()

            if admin:
                fingerprint = hashlib.sha256(admin["password"].encode()).hexdigest()
                serializer = URLSafeTimedSerializer(
                    app.secret_key, salt="smartfix-admin-reset-v1"
                )
                token = serializer.dumps({"id": admin["id"], "fp": fingerprint})
                link = url_for("admin_reset_password", token=token, _external=True)
                try:
                    send_reset_email(recovery_email, link)
                except (OSError, RuntimeError):
                    app.logger.exception("Could not send admin password reset email")
                    return "Email service is temporarily unavailable. Please try again later.", 503

        return "If this email is authorized, a password reset link has been sent. Check your inbox."

    return render_template("admin_forgot_password.html")


@app.route("/admin-reset-password/<token>", methods=["GET", "POST"])
def admin_reset_password(token):
    serializer = URLSafeTimedSerializer(
        app.secret_key, salt="smartfix-admin-reset-v1"
    )
    try:
        data = serializer.loads(token, max_age=900)
    except (BadSignature, SignatureExpired):
        return "Reset link is invalid or expired. Please request a new one.", 400

    conn = get_db_connection()
    admin = conn.execute(
        "SELECT id, password FROM admins WHERE id = ? AND username = ?",
        (data.get("id"), "admin")
    ).fetchone()

    if (not admin or
            hashlib.sha256(admin["password"].encode()).hexdigest() != data.get("fp")):
        conn.close()
        return "Reset link is invalid or has already been used.", 400

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 8 or password != confirm:
            conn.close()
            return "Passwords must match and contain at least 8 characters.", 400
        conn.execute(
            "UPDATE admins SET password = ? WHERE id = ?",
            (generate_password_hash(password), admin["id"])
        )
        conn.commit()
        conn.close()
        session.pop("admin_id", None)
        session.pop("admin_username", None)
        return redirect(url_for("admin_login"))

    conn.close()
    return render_template("admin_reset_password.html")


# ==================================================
# ADMIN DASHBOARD
# ==================================================

@app.route("/admin")
def admin_dashboard():

    if "admin_id" not in session:
        return redirect("/admin-login")

    conn = get_db_connection()

    customers = conn.execute(
        "SELECT COUNT(*) FROM customers"
    ).fetchone()[0]

    total_requests = conn.execute(
        "SELECT COUNT(*) FROM repair_requests"
    ).fetchone()[0]

    pending_requests = conn.execute(
        "SELECT COUNT(*) FROM repair_requests WHERE status = 'Pending'"
    ).fetchone()[0]

    completed_requests = conn.execute(
        "SELECT COUNT(*) FROM repair_requests WHERE status = 'Completed'"
    ).fetchone()[0]

    technicians = conn.execute(
        "SELECT COUNT(*) FROM technicians"
    ).fetchone()[0]

    assigned_requests = conn.execute(
        "SELECT COUNT(*) FROM repair_requests WHERE technician_id IS NOT NULL"
    ).fetchone()[0]

    conn.close()

    return render_template(
        "admin_dashboard.html",
        customers=customers,
        total_requests=total_requests,
        pending_requests=pending_requests,
        completed_requests=completed_requests,
        technicians=technicians,
        assigned_requests=assigned_requests
    )


# ==================================================
# ADMIN REPAIR REQUESTS
# ==================================================

@app.route("/admin/repairs")
def admin_repairs():

    if "admin_id" not in session:
        return redirect("/admin-login")

    conn = get_db_connection()

    repairs = conn.execute("""
        SELECT repair_requests.*,
               technicians.name AS technician_name
        FROM repair_requests
        LEFT JOIN technicians
        ON repair_requests.technician_id = technicians.id
        ORDER BY repair_requests.id DESC
    """).fetchall()

    technicians = conn.execute(
        "SELECT * FROM technicians"
    ).fetchall()

    conn.close()

    return render_template(
        "admin_repairs.html",
        repairs=repairs,
        technicians=technicians
    )


# ==================================================
# UPDATE REPAIR STATUS
# ==================================================

@app.route(
    "/admin/update-status/<int:request_id>",
    methods=["POST"]
)
def update_status(request_id):

    if "admin_id" not in session:
        return redirect("/admin-login")

    status = request.form["status"]

    conn = get_db_connection()

    conn.execute("""
        UPDATE repair_requests
        SET status = ?
        WHERE id = ?
    """, (
        status,
        request_id
    ))

    conn.commit()
    conn.close()

    return redirect("/admin/repairs")


# ==================================================
# ASSIGN TECHNICIAN
# ==================================================

@app.route(
    "/admin/assign-technician/<int:request_id>",
    methods=["POST"]
)
def assign_technician(request_id):

    if "admin_id" not in session:
        return redirect("/admin-login")

    technician_id = request.form["technician_id"]

    conn = get_db_connection()

    conn.execute("""
        UPDATE repair_requests
        SET technician_id = ?, status = 'Assigned'
        WHERE id = ?
    """, (
        technician_id,
        request_id
    ))

    conn.commit()
    conn.close()

    return redirect("/admin/repairs")


# ==================================================
# ADMIN CUSTOMERS
# ==================================================

@app.route("/admin/customers")
def admin_customers():

    if "admin_id" not in session:
        return redirect("/admin-login")

    conn = get_db_connection()

    customers = conn.execute(
        "SELECT * FROM customers ORDER BY id DESC"
    ).fetchall()

    conn.close()

    return render_template(
        "admin_customers.html",
        customers=customers
    )


# ==================================================
# ADMIN TECHNICIANS
# ==================================================

@app.route("/admin/technicians")
def admin_technicians():

    if "admin_id" not in session:
        return redirect("/admin-login")

    conn = get_db_connection()

    technicians = conn.execute(
        "SELECT * FROM technicians ORDER BY id DESC"
    ).fetchall()

    conn.close()

    return render_template(
        "admin_technicians.html",
        technicians=technicians
    )


# ==================================================
# ADMIN LOGOUT
# ==================================================

@app.route("/admin-logout")
def admin_logout():

    session.pop("admin_id", None)
    session.pop("admin_username", None)

    return redirect("/admin-login")


# ==================================================
# TECHNICIAN REGISTRATION
# ==================================================

@app.route(
    "/technician-register",
    methods=["GET", "POST"]
)
def technician_register():

    if request.method == "POST":

        name = request.form["name"]
        email = request.form["email"]
        mobile = request.form["mobile"]
        specialization = request.form["specialization"]
        password = request.form["password"]

        conn = get_db_connection()

        try:

            conn.execute("""
                INSERT INTO technicians
                (name, email, mobile,
                 specialization, password)
                VALUES (?, ?, ?, ?, ?)
            """, (
                name,
                email,
                mobile,
                specialization,
                generate_password_hash(password)
            ))

            conn.commit()

        except sqlite3.IntegrityError:

            conn.close()

            return "Email already registered."

        conn.close()

        return redirect("/technician-login")

    return render_template("technician_register.html")


# ==================================================
# TECHNICIAN LOGIN
# ==================================================

@app.route(
    "/technician-login",
    methods=["GET", "POST"]
)
def technician_login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()

        technician = conn.execute("""
            SELECT * FROM technicians
            WHERE email = ?
        """, (email,)).fetchone()

        conn.close()

        if technician and password_matches(
            technician["password"],
            password
        ):

            session["technician_id"] = technician["id"]
            session["technician_name"] = technician["name"]

            return redirect("/technician-dashboard")

        return "Invalid email or password."

    return render_template("technician_login.html")


# ==================================================
# TECHNICIAN FORGOT PASSWORD (BREVO)
# ==================================================

@app.route("/technician-forgot-password", methods=["GET", "POST"])
def technician_forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        conn = get_db_connection()
        technician = conn.execute(
            "SELECT id, email, password FROM technicians WHERE lower(email) = ?",
            (email,)
        ).fetchone()
        conn.close()

        if technician:
            fingerprint = hashlib.sha256(technician["password"].encode()).hexdigest()
            serializer = URLSafeTimedSerializer(
                app.secret_key, salt="smartfix-technician-reset-v1"
            )
            token = serializer.dumps({"id": technician["id"], "fp": fingerprint})
            link = url_for("technician_reset_password", token=token, _external=True)
            try:
                send_reset_email(technician["email"], link)
            except (OSError, RuntimeError):
                app.logger.exception("Could not send technician password reset email")
                return "Email service is temporarily unavailable. Please try again later.", 503

        return "If this technician email is registered, a reset link has been sent. Check your inbox."

    return render_template("technician_forgot_password.html")


@app.route("/technician-reset-password/<token>", methods=["GET", "POST"])
def technician_reset_password(token):
    serializer = URLSafeTimedSerializer(
        app.secret_key, salt="smartfix-technician-reset-v1"
    )
    try:
        data = serializer.loads(token, max_age=900)
    except (BadSignature, SignatureExpired):
        return "Reset link is invalid or expired. Please request a new one.", 400

    conn = get_db_connection()
    technician = conn.execute(
        "SELECT id, password FROM technicians WHERE id = ?", (data.get("id"),)
    ).fetchone()
    if (not technician or
            hashlib.sha256(technician["password"].encode()).hexdigest() != data.get("fp")):
        conn.close()
        return "Reset link is invalid or has already been used.", 400

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 8 or password != confirm:
            conn.close()
            return "Passwords must match and contain at least 8 characters.", 400
        conn.execute(
            "UPDATE technicians SET password = ? WHERE id = ?",
            (generate_password_hash(password), technician["id"])
        )
        conn.commit()
        conn.close()
        return redirect(url_for("technician_login"))

    conn.close()
    return render_template("technician_reset_password.html")


# ==================================================
# TECHNICIAN DASHBOARD
# ==================================================

@app.route("/technician-dashboard")
def technician_dashboard():

    if "technician_id" not in session:
        return redirect("/technician-login")

    conn = get_db_connection()

    requests_data = conn.execute("""
        SELECT *
        FROM repair_requests
        WHERE technician_id = ?
        ORDER BY id DESC
    """, (
        session["technician_id"],
    )).fetchall()

    conn.close()

    return render_template(
        "technician_dashboard.html",
        name=session["technician_name"],
        requests=requests_data
    )


# ==================================================
# TECHNICIAN UPDATE STATUS
# ==================================================

@app.route(
    "/technician/update-status/<int:request_id>",
    methods=["POST"]
)
def technician_update_status(request_id):

    if "technician_id" not in session:
        return redirect("/technician-login")

    status = request.form["status"]

    conn = get_db_connection()

    conn.execute("""
        UPDATE repair_requests
        SET status = ?
        WHERE id = ? AND technician_id = ?
    """, (
        status,
        request_id,
        session["technician_id"]
    ))

    conn.commit()
    conn.close()

    return redirect("/technician-dashboard")


# ==================================================
# TECHNICIAN LOGOUT
# ==================================================

@app.route("/technician-logout")
def technician_logout():

    session.pop("technician_id", None)
    session.pop("technician_name", None)

    return redirect("/technician-login")


# ==================================================
# INITIALIZE DATABASE
# ==================================================

create_database()
create_repair_table()
create_admin_table()
create_technician_table()


# ==================================================
# RUN APPLICATION
# ==================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
