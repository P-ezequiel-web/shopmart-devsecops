"""
ShopMart — módulo de laboratorio Web App Security + SDLC
==========================================================

Aplicación de e-commerce (estilo Amazon/eBay) construida con vulnerabilidades
DELIBERADAS para servir como objetivo de un pipeline DevSecOps con detección
y remediación automática.

Vulnerabilidades incluidas a propósito (ver README.md para el detalle completo):

  1. SQL Injection (CWE-89)      -> rutas /login y /search
  2. XSS reflejado y almacenado  -> templates/search.html y templates/product.html
     (CWE-79)
  3. Secretos hardcodeados       -> constantes más abajo en este archivo
     (CWE-798)
  4. Dependencia con CVE conocido -> requirements.txt (PyYAML==5.3.1)

NO despliegues esta aplicación en una red pública ni reutilices este código
fuera de un entorno de laboratorio controlado.
"""
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, g, flash
)
import sqlite3

from database import DATABASE, init_db

app = Flask(__name__)

# ---------------------------------------------------------------------------
# VULNERABILIDAD 3: Secretos hardcodeados en el código fuente (CWE-798)
#
# Estas credenciales/llaves quedan versionadas en Git tal cual, exactamente
# como ocurre en incidentes reales cuando alguien commitea un .env por error
# o pega una API key "temporalmente" en el código. Un escáner de secretos
# (Gitleaks, TruffleHog, GitHub Secret Scanning, detect-secrets) debe
# detectar cada una de estas líneas.
#
# Además, como app.secret_key firma las cookies de sesión de Flask, cualquiera
# que lea este archivo en el repositorio puede forjar una cookie de sesión
# válida (por ejemplo session["user"] = "admin") sin necesitar la contraseña.
# ---------------------------------------------------------------------------
app.secret_key = "s3cr3t_k3y_2024_shopmart_flask_app"

ADMIN_PASSWORD = "Admin123!"
STRIPE_API_KEY = "sk_live_51Hc3F2KZ9Y8pXwLq7T6vN4rBjD0eA1oM9sZQxample"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_ADMIN_CONNECTION_STRING = "postgresql://shopmart_admin:SuperClave2024@10.0.0.15:5432/shopmart_prod"


# ---------------------------------------------------------------------------
# Conexión a base de datos
# ---------------------------------------------------------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def get_categories():
    db = get_db()
    rows = db.execute("SELECT DISTINCT category FROM products ORDER BY category").fetchall()
    return [r["category"] for r in rows]


def get_cart_items():
    cart = session.get("cart", {})
    if not cart:
        return [], 0.0
    db = get_db()
    items = []
    total = 0.0
    for product_id, qty in cart.items():
        row = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if row:
            item = dict(row)
            item["qty"] = qty
            items.append(item)
            total += item["price"] * qty
    return items, total


@app.context_processor
def inject_cart_count():
    cart = session.get("cart", {})
    return {"cart_count": sum(cart.values()), "categories": get_categories()}


# ---------------------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    db = get_db()
    cat = request.args.get("cat", "")
    if cat:
        # Consulta parametrizada correcta (a diferencia de /search más abajo)
        products = db.execute(
            "SELECT * FROM products WHERE category = ? ORDER BY id", (cat,)
        ).fetchall()
    else:
        products = db.execute("SELECT * FROM products ORDER BY id").fetchall()

    deals = db.execute(
        "SELECT * FROM products WHERE badge IS NOT NULL ORDER BY id LIMIT 3"
    ).fetchall()

    return render_template(
        "index.html", products=products, deals=deals, current_cat=cat
    )


@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()

    # -----------------------------------------------------------------
    # VULNERABILIDAD 1a: SQL Injection en la búsqueda de productos (CWE-89)
    #
    # El término de búsqueda se concatena directamente dentro del SQL en
    # lugar de usar parámetros ligados (`?`). Esto permite manipular la
    # consulta, por ejemplo:
    #
    #   /search?q=' UNION SELECT id,username,password,1,1,1,1,1 FROM users--
    #
    # La forma correcta (remediación) sería:
    #   db.execute(
    #       "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
    #       (f"%{q}%", f"%{q}%"),
    #   )
    # -----------------------------------------------------------------
    query = "SELECT * FROM products WHERE name LIKE '%" + q + "%' OR description LIKE '%" + q + "%'"
    try:
        products = db.execute(query).fetchall()
    except sqlite3.OperationalError:
        products = []

    return render_template("search.html", products=products, query=q)


@app.route("/product/<int:product_id>", methods=["GET", "POST"])
def product(product_id):
    db = get_db()

    if request.method == "POST":
        author = request.form.get("author", "").strip() or "Anónimo"
        comment = request.form.get("comment", "").strip()
        if comment:
            # Esta parte SÍ usa parámetros ligados: el riesgo de XSS almacenado
            # no está en cómo se guarda el comentario, sino en cómo se
            # renderiza después (ver templates/product.html, filtro `|safe`).
            db.execute(
                "INSERT INTO reviews (product_id, author, comment) VALUES (?, ?, ?)",
                (product_id, author, comment),
            )
            db.commit()

    prod = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    reviews = db.execute(
        "SELECT * FROM reviews WHERE product_id = ? ORDER BY id DESC", (product_id,)
    ).fetchall()

    return render_template("product.html", product=prod, reviews=reviews)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()

        # -----------------------------------------------------------------
        # VULNERABILIDAD 1b: SQL Injection en autenticación (CWE-89)
        #
        # Permite un bypass de login clásico, por ejemplo usando como
        # usuario:   admin' --
        # (con cualquier contraseña), o usando como contraseña:
        #   ' OR '1'='1
        #
        # Remediación: consulta parametrizada + verificación de contraseña
        # con hash (p. ej. werkzeug.security.check_password_hash) en vez de
        # comparar texto plano.
        # -----------------------------------------------------------------
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        try:
            user = db.execute(query).fetchone()
        except sqlite3.OperationalError:
            user = None

        if user:
            session["user"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            flash(f"Bienvenido/a de nuevo, {user['username']}.")
            return redirect(url_for("index"))
        error = "Usuario o contraseña incorrectos."

    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()

        if not username or not password:
            error = "Usuario y contraseña son obligatorios."
        else:
            existing = db.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing:
                error = "Ese usuario ya existe."
            else:
                db.execute(
                    "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
                    (username, password),
                )
                db.commit()
                session["user"] = username
                session["is_admin"] = False
                flash("Cuenta creada correctamente. ¡Bienvenido/a!")
                return redirect(url_for("index"))

    return render_template("register.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/cart")
def cart():
    items, total = get_cart_items()
    return render_template("cart.html", items=items, total=total)


@app.route("/cart/add/<int:product_id>", methods=["POST"])
def cart_add(product_id):
    cart = session.get("cart", {})
    key = str(product_id)
    cart[key] = cart.get(key, 0) + 1
    session["cart"] = cart
    flash("Producto añadido al carrito.")
    return redirect(url_for("product", product_id=product_id))


@app.route("/cart/remove/<int:product_id>")
def cart_remove(product_id):
    cart = session.get("cart", {})
    cart.pop(str(product_id), None)
    session["cart"] = cart
    return redirect(url_for("cart"))


if __name__ == "__main__":
    init_db()
    # debug=True también es una mala práctica para producción (expone el
    # depurador interactivo de Werkzeug), coherente con el resto del
    # laboratorio. No la actives en un entorno expuesto.
    app.run(host="127.0.0.1", port=5000, debug=True)
