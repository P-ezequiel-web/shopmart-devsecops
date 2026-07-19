"""
Inicializa y siembra la base de datos SQLite de ShopMart.

Nota de laboratorio: las contraseñas se guardan en texto plano a propósito
(CWE-256) para mantener simple la demostración de inyección SQL en /login,
donde la consulta compara username/password directamente. No repliques este
patrón fuera de este entorno de práctica.
"""
import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shopmart.db")

PRODUCTS = [
    # name, category, price, rating, stock, description, icon, badge
    ("Auriculares Inalámbricos Pro", "Electrónica", 89.99, 4.5, 23,
     "Cancelación activa de ruido, 30 horas de batería y estuche de carga rápida.",
     "🎧", "-20%"),
    ("Laptop UltraSlim 14\"", "Electrónica", 649.00, 4.2, 8,
     "Procesador de 8 núcleos, 16GB RAM y pantalla antirreflejo full HD.",
     "💻", None),
    ("Cafetera Programable 12 tazas", "Hogar", 54.50, 4.7, 40,
     "Temporizador programable, jarra térmica y filtro reutilizable incluido.",
     "☕", None),
    ("Mochila Urbana Impermeable", "Moda", 39.90, 4.6, 65,
     "Compartimento acolchado para laptop de 15\", puerto USB y tela repelente al agua.",
     "🎒", "Nuevo"),
    ("Zapatillas Running AirFlex", "Deportes", 72.00, 4.3, 30,
     "Suela de espuma reactiva y malla transpirable para largas distancias.",
     "👟", "-15%"),
    ("Smartwatch FitTrack 2", "Electrónica", 99.99, 4.1, 15,
     "Monitor de ritmo cardíaco, GPS integrado y resistencia al agua 5ATM.",
     "⌚", None),
    ("Set de Cuchillos de Cocina (6 pzas)", "Hogar", 45.00, 4.8, 22,
     "Acero inoxidable forjado con bloque de almacenamiento en madera.",
     "🔪", None),
    ("Lámpara de Escritorio LED", "Hogar", 22.75, 4.4, 50,
     "Tres tonos de luz regulables y brazo articulado de aluminio.",
     "💡", "Nuevo"),
    ("Bicicleta Plegable Urbana", "Deportes", 210.00, 4.0, 5,
     "Cuadro de aluminio, plegado en 10 segundos, ideal para combinar con transporte público.",
     "🚲", None),
]

USERS = [
    # username, password (texto plano, ver nota arriba), is_admin
    ("admin", "Admin123!", 1),
    ("juan.perez", "password123", 0),
    ("maria.lopez", "maria2024", 0),
]

SAMPLE_REVIEWS = [
    (1, "Carla R.", "Excelente calidad de sonido, los uso todos los días para trabajar."),
    (1, "Diego M.", "Buena batería, aunque el estuche podría ser más compacto."),
    (3, "Fernanda T.", "La cafetera llegó a tiempo y el café sabe genial. Muy recomendable."),
]


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(reset: bool = False):
    if reset and os.path.exists(DATABASE):
        os.remove(DATABASE)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            rating REAL NOT NULL,
            stock INTEGER NOT NULL,
            description TEXT NOT NULL,
            icon TEXT NOT NULL,
            badge TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            author TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    """)

    cur.execute("SELECT COUNT(*) FROM products")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO products (name, category, price, rating, stock, description, icon, badge) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            PRODUCTS,
        )

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            USERS,
        )

    cur.execute("SELECT COUNT(*) FROM reviews")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO reviews (product_id, author, comment) VALUES (?, ?, ?)",
            SAMPLE_REVIEWS,
        )

    conn.commit()
    conn.close()
    print(f"Base de datos lista en: {DATABASE}")


if __name__ == "__main__":
    init_db(reset=True)
