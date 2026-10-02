from flask import Flask, render_template, request, redirect, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "smartfix_secret_key"

DATABASE = "smartfix.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


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


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        mobile = request.form["mobile"]
        password = request.form["password"]
        address = request.form["address"]

        conn = get_db_connection()

        try:
            conn.execute("""
                INSERT INTO customers
                (name, email, mobile, password, address)
                VALUES (?, ?, ?, ?, ?)
            """, (name, email, mobile, password, address))

            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()
            return "Email already registered."

        conn.close()
        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()

        customer = conn.execute("""
            SELECT * FROM customers
            WHERE email = ? AND password = ?
        """, (email, password)).fetchone()

        conn.close()

        if customer:
            session["customer_id"] = customer["id"]
            session["customer_name"] = customer["name"]
            return redirect("/dashboard")

        return "Invalid email or password."

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "customer_id" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        name=session["customer_name"]
    )


@app.route("/repair-request", methods=["GET", "POST"])
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
            (customer_name, mobile, service_type, description, address, status)
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
    """, (session["customer_name"],)).fetchall()

    conn.close()

    return render_template(
        "my_requests.html",
        requests=requests_data
    )


@app.route("/logout")
def logout():
    session.pop("customer_id", None)
    session.pop("customer_name", None)
    return redirect("/")


@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()

        admin = conn.execute("""
            SELECT * FROM admins
            WHERE username = ? AND password = ?
        """, (username, password)).fetchone()

        conn.close()

        if admin:
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            return redirect("/admin")

        return "Invalid admin username or password."

    return render_template("admin_login.html")


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


@app.route("/admin/update-status/<int:request_id>", methods=["POST"])
def update_status(request_id):
    if "admin_id" not in session:
        return redirect("/admin-login")

    status = request.form["status"]

    conn = get_db_connection()

    conn.execute("""
        UPDATE repair_requests
        SET status = ?
        WHERE id = ?
    """, (status, request_id))

    conn.commit()
    conn.close()

    return redirect("/admin/repairs")


@app.route("/admin/assign-technician/<int:request_id>", methods=["POST"])
def assign_technician(request_id):
    if "admin_id" not in session:
        return redirect("/admin-login")

    technician_id = request.form["technician_id"]

    conn = get_db_connection()

    conn.execute("""
        UPDATE repair_requests
        SET technician_id = ?, status = 'Assigned'
        WHERE id = ?
    """, (technician_id, request_id))

    conn.commit()
    conn.close()

    return redirect("/admin/repairs")


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


@app.route("/admin-logout")
def admin_logout():
    session.pop("admin_id", None)
    session.pop("admin_username", None)
    return redirect("/admin-login")


@app.route("/technician-register", methods=["GET", "POST"])
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
                (name, email, mobile, specialization, password)
                VALUES (?, ?, ?, ?, ?)
            """, (
                name,
                email,
                mobile,
                specialization,
                password
            ))

            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()
            return "Email already registered."

        conn.close()
        return redirect("/technician-login")

    return render_template("technician_register.html")


@app.route("/technician-login", methods=["GET", "POST"])
def technician_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()

        technician = conn.execute("""
            SELECT * FROM technicians
            WHERE email = ? AND password = ?
        """, (email, password)).fetchone()

        conn.close()

        if technician:
            session["technician_id"] = technician["id"]
            session["technician_name"] = technician["name"]
            return redirect("/technician-dashboard")

        return "Invalid email or password."

    return render_template("technician_login.html")


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
    """, (session["technician_id"],)).fetchall()

    conn.close()

    return render_template(
        "technician_dashboard.html",
        name=session["technician_name"],
        requests=requests_data
    )


@app.route("/technician/update-status/<int:request_id>", methods=["POST"])
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


@app.route("/technician-logout")
def technician_logout():
    session.pop("technician_id", None)
    session.pop("technician_name", None)
    return redirect("/technician-login")


create_database()
create_repair_table()
create_admin_table()
create_technician_table()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )