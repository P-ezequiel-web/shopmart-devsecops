# ShopMart — Laboratorio de Web App Security + SDLC

Tienda online (estilo Amazon/eBay) construida con **Flask**, con cuatro
vulnerabilidades **deliberadas** para servir de objetivo a un pipeline
DevSecOps (CI/CD con detección y remediación automática).

> ⚠️ **Uso exclusivo en laboratorio.** No despliegues esta app en una red
> pública, no reutilices este código en un proyecto real y no subas la
> `shopmart.db` generada (ya está en `.gitignore`). El objetivo es que
> herramientas de análisis (SAST/DAST/SCA/secret scanning) la detecten y,
> en pasos posteriores de tu pipeline, la remedien automáticamente.

## Cómo correrlo localmente

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

La app queda disponible en `http://127.0.0.1:5000`. La base de datos SQLite
(`shopmart.db`) se crea y siembra sola en el primer arranque. Usuarios de
prueba: `admin` / `Admin123!`, `juan.perez` / `password123`.

## Mapa de vulnerabilidades

| # | Vulnerabilidad | CWE | Ubicación | Categoría de escaneo |
|---|---|---|---|---|
| 1 | SQL Injection | CWE-89 | `app.py` → `login()`, `search()` | SAST + DAST |
| 2 | XSS reflejado | CWE-79 | `templates/search.html` | SAST + DAST |
| 2b | XSS almacenado | CWE-79 | `templates/product.html` (reseñas) | SAST + DAST |
| 3 | Secretos hardcodeados | CWE-798 | `app.py`, líneas ~40-45 | Secret scanning |
| 4 | Dependencia con CVE conocido | CWE-1104 | `requirements.txt` → `PyYAML==5.3.1` (CVE-2020-14343) | SCA |

Cada punto está señalado con un comentario `VULNERABILIDAD` en el código
fuente para que sea fácil de ubicar.

---

### 1. SQL Injection (CWE-89)

**Dónde:** `app.py`, rutas `/login` y `/search`. Ambas construyen la consulta
SQL concatenando el input del usuario en vez de usar parámetros ligados
(`?`), a diferencia del resto del código (por ejemplo el filtro por
categoría en `/`, que sí es seguro y sirve de contraste).

**Cómo probarla localmente (solo contra tu propia instancia):**
- Bypass de login: en el campo *usuario* escribe `admin' --` y deja
  cualquier contraseña.
- Búsqueda: `/search?q=%'--` altera la consulta de forma visible en los
  resultados.

**Remediación esperada:** reemplazar la concatenación por consultas
parametrizadas (`db.execute("... WHERE username = ?", (username,))`) y
verificar contraseñas con hash (`werkzeug.security.check_password_hash`) en
vez de comparar texto plano.

**Herramientas típicas para detectarla:** Bandit y Semgrep (SAST, reglas
`B608`/`sql-injection`), CodeQL, y OWASP ZAP o sqlmap en la fase DAST contra
la app corriendo en el pipeline.

---

### 2. Cross-Site Scripting — reflejado y almacenado (CWE-79)

**Reflejado:** `templates/search.html` imprime el término de búsqueda con
`{{ query|safe }}`, desactivando el autoescape que Jinja2 aplica por
defecto. Prueba: `/search?q=<script>alert(1)</script>`.

**Almacenado:** `templates/product.html` imprime cada reseña con
`{{ r['comment']|safe }}`. Cualquier visitante que publique una reseña con
HTML/JS lo ejecutará en el navegador de todo el que visite esa ficha de
producto. Prueba: en el formulario de reseñas de cualquier producto, escribe
`<img src=x onerror=alert(document.cookie)>` como comentario.

**Por qué importa junto con la vulnerabilidad #3:** como `app.secret_key`
está hardcodeada y expuesta en el repo, un atacante que combine el XSS
almacenado con esa clave podría, en un escenario real, robar y falsificar
cookies de sesión con mucha más facilidad.

**Remediación esperada:** quitar el filtro `|safe` y dejar que Jinja2
escape por defecto; si en algún caso se necesita HTML enriquecido, sanear
con una librería como `bleach` antes de guardar o renderizar.

**Herramientas típicas:** Semgrep/Bandit (patrón `|safe` con datos de
usuario), CodeQL, OWASP ZAP en DAST.

---

### 3. Secretos hardcodeados (CWE-798)

**Dónde:** `app.py`, bloque cerca del inicio del archivo — `secret_key` de
Flask, una llave de Stripe, credenciales de AWS y una cadena de conexión con
usuario/contraseña de base de datos (todas son valores de ejemplo, no
credenciales reales, pero con el formato que un escáner de secretos debe
reconocer).

**Remediación esperada:** mover todo a variables de entorno (`os.environ`)
o a un gestor de secretos (AWS Secrets Manager, HashiCorp Vault, GitHub
Actions secrets), y rotar cualquier credencial que haya llegado a estar en
el historial de Git.

**Herramientas típicas:** Gitleaks o TruffleHog como *pre-commit hook* y
como job de CI, además del secret scanning nativo de GitHub (Push
Protection / Advanced Security).

---

### 4. Dependencia con CVE conocido (CWE-1104 / SCA)

**Dónde:** `requirements.txt` → `PyYAML==5.3.1`, afectada por
**CVE-2020-14343** (ejecución de código arbitrario al deserializar YAML no
confiable con `yaml.load()`/`FullLoader`, corregido en la 5.4).

**Remediación esperada:** subir la versión a `PyYAML>=6.0` en
`requirements.txt`. Este es el caso ideal para una remediación
**automática** vía Dependabot (PR automático) o `pip-audit --fix`.

**Herramientas típicas:** GitHub Dependabot (alerts + auto PRs), `pip-audit`,
`safety`, Snyk, Trivy (`trivy fs .`).

---

## Sugerencia de etapas para el pipeline DevSecOps

| Etapa | Qué detecta | Herramientas sugeridas |
|---|---|---|
| Pre-commit / secret scan | Vulnerabilidad 3 | Gitleaks, TruffleHog |
| SAST (análisis estático) | Vulnerabilidades 1 y 2 | Bandit, Semgrep, CodeQL |
| SCA (composición de software) | Vulnerabilidad 4 | Dependabot, pip-audit, Trivy |
| DAST (dinámico, app corriendo) | Vulnerabilidades 1 y 2 en tiempo real | OWASP ZAP Baseline Scan |
| Remediación automática | 3 y 4 sobre todo | Dependabot auto-PR, bot que reemplace `\|safe` / concatenación SQL vía PR sugerido |

Con este mapa ya puedes definir los *jobs* de tu workflow de GitHub Actions
(por ejemplo `bandit -r . -ll`, `semgrep --config auto`, `gitleaks detect`,
`pip-audit -r requirements.txt`, y un job de ZAP Baseline apuntando a la app
levantada en un contenedor efímero del propio workflow).
