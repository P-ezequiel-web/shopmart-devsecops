# BopZ — Reporte de Pentesting

**Objetivo:** http://127.0.0.1:5000  
**Fecha:** 2026-08-01 15:36 EDT  
**Duración:** 44.6s  
**Requests enviados:** 90

## Resumen de hallazgos

| Severidad | Cantidad |
|---|---|
| CRITICAL | 35 |
| HIGH | 3 |
| MEDIUM | 14 |
| LOW | 14 |

## Detalle de hallazgos

### [CRITICAL] Flask secret_key hardcodeada en código fuente (STATIC-SEC-001)
**CWE:** CWE-798  
**URL:** `repo:app.py:44`  

**Evidencia:**
```
Archivo: app.py  línea: 44
app.secret_key = ****REDACTED****
```

La secret_key de Flask está versionada en el repositorio. Cualquiera que lea el código puede forjar cookies de sesión firmadas con esa clave sin conocer ninguna contraseña.

**Remediación:** Generar con secrets.token_hex(32) y cargar desde variable de entorno: app.secret_key = os.environ['SECRET_KEY']

---

### [CRITICAL] Stripe API Key hardcodeada (STATIC-SEC-003)
**CWE:** CWE-798  
**URL:** `repo:app.py:47`  

**Evidencia:**
```
Archivo: app.py  línea: 47
STRIPE_API_KEY = ****REDACTED****
```

Clave de Stripe en texto plano en el código. Permite realizar cargos, reembolsos y acceder a datos de clientes.

**Remediación:** Cargar desde variable de entorno (os.environ['STRIPE_API_KEY']). Rotar la clave inmediatamente en el dashboard de Stripe.

---

### [CRITICAL] AWS Access Key ID hardcodeada (STATIC-SEC-004)
**CWE:** CWE-798  
**URL:** `repo:app.py:48`  

**Evidencia:**
```
Archivo: app.py  línea: 48
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
```

Access Key ID de AWS en texto plano. Combinada con la Secret Access Key, da acceso completo a los servicios AWS de la cuenta.

**Remediación:** Usar IAM Roles o variables de entorno. Revocar la clave en la consola de IAM inmediatamente.

---

### [CRITICAL] AWS Secret Access Key hardcodeada (STATIC-SEC-005)
**CWE:** CWE-798  
**URL:** `repo:app.py:49`  

**Evidencia:**
```
Archivo: app.py  línea: 49
AWS_SECRET_ACCESS_KEY = ****REDACTED****
```

Secret Access Key de AWS en texto plano. Junto al Access Key ID permite acceso completo a AWS.

**Remediación:** Rotar inmediatamente en IAM. Cargar desde variable de entorno o AWS Secrets Manager.

---

### [CRITICAL] Connection string con credenciales hardcodeadas (STATIC-SEC-006)
**CWE:** CWE-798  
**URL:** `repo:app.py:50`  

**Evidencia:**
```
Archivo: app.py  línea: 50
DB_ADMIN_CONNECTION_STRING = ****REDACTED****
```

URL de base de datos con usuario y contraseña en texto plano. Expone las credenciales de producción a cualquier lector del repo.

**Remediación:** Usar variable de entorno DATABASE_URL o un gestor de secretos (HashiCorp Vault, AWS Secrets Manager).

---

### [CRITICAL] Dependencia vulnerable: PyYAML==5.3.1 (STATIC-DEP-005)
**CWE:** CWE-1395  
**URL:** `repo:requirements.txt`  

**Evidencia:**
```
Paquete: PyYAML==5.3.1  (declarado en requirements.txt)
  [CRITICAL] GHSA-8q59-q68h-6hv4 — Improper Input Validation in PyYAML (CVE-2020-14343, PYSEC-2021-142)
  [UNKNOWN] PYSEC-2021-142 — PYSEC-2021-142 (CVE-2020-14343, GHSA-8q59-q68h-6hv4)
```

La versión 5.3.1 de PyYAML tiene 2 vulnerabilidad(es) conocida(s) registrada(s) en OSV.dev / National Vulnerability Database.
CVEs: CVE-2020-14343

**Remediación:** Actualizar PyYAML a la versión más reciente estable (`pip install --upgrade PyYAML`) y anclar la versión en requirements.txt.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'username' (SQLI-001)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/login`  

**Evidencia:**
```
POST username=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/, 9277 bytes
POST username=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/login, 3750 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'password' (SQLI-002)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/login`  

**Evidencia:**
```
POST password=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/, 9202 bytes
POST password=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/login, 3700 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'author' (SQLI-003)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/1`  

**Evidencia:**
```
POST author=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/1, 155800 bytes
POST author=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/1, 156336 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'comment' (SQLI-004)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/1`  

**Evidencia:**
```
POST comment=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/1, 156856 bytes
POST comment=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/1, 157376 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'author' (SQLI-005)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/2`  

**Evidencia:**
```
POST author=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/2, 148034 bytes
POST author=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/2, 148570 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'comment' (SQLI-006)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/2`  

**Evidencia:**
```
POST comment=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/2, 149090 bytes
POST comment=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/2, 149610 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'author' (SQLI-007)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/3`  

**Evidencia:**
```
POST author=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/3, 149672 bytes
POST author=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/3, 150208 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'comment' (SQLI-008)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/3`  

**Evidencia:**
```
POST comment=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/3, 150728 bytes
POST comment=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/3, 151248 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'author' (SQLI-009)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/4`  

**Evidencia:**
```
POST author=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/4, 149087 bytes
POST author=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/4, 149623 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'comment' (SQLI-010)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/4`  

**Evidencia:**
```
POST comment=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/4, 150143 bytes
POST comment=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/4, 150663 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'author' (SQLI-011)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/5`  

**Evidencia:**
```
POST author=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/5, 148560 bytes
POST author=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/5, 149096 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'comment' (SQLI-012)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/5`  

**Evidencia:**
```
POST comment=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/5, 149616 bytes
POST comment=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/5, 150136 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'author' (SQLI-013)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/6`  

**Evidencia:**
```
POST author=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/6, 148557 bytes
POST author=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/6, 149093 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'comment' (SQLI-014)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/6`  

**Evidencia:**
```
POST comment=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/6, 149613 bytes
POST comment=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/6, 150133 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'author' (SQLI-015)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/7`  

**Evidencia:**
```
POST author=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/7, 148561 bytes
POST author=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/7, 149097 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'comment' (SQLI-016)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/7`  

**Evidencia:**
```
POST comment=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/7, 149617 bytes
POST comment=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/7, 150137 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'author' (SQLI-017)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/8`  

**Evidencia:**
```
POST author=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/8, 148547 bytes
POST author=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/8, 149083 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'comment' (SQLI-018)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/8`  

**Evidencia:**
```
POST comment=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/8, 149603 bytes
POST comment=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/8, 150123 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'author' (SQLI-019)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/9`  

**Evidencia:**
```
POST author=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/9, 148572 bytes
POST author=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/9, 149108 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] Posible SQL Injection / bypass en campo POST 'comment' (SQLI-020)
**CWE:** CWE-89  
**URL:** `http://127.0.0.1:5000/product/9`  

**Evidencia:**
```
POST comment=zzz' OR '1'='1  -> status 200, redirige a http://127.0.0.1:5000/product/9, 149628 bytes
POST comment=zzz' OR '1'='2  -> status 200, redirige a http://127.0.0.1:5000/product/9, 150148 bytes
```

La respuesta cambia significativamente entre una condición SQL verdadera y una falsa en este campo (status, URL final o tamaño), lo que sugiere concatenación directa en una consulta -por ejemplo, un login construido con f-strings/concatenación en vez de parámetros.

**Remediación:** Usar consultas parametrizadas y verificar contraseñas con hash (werkzeug.security.check_password_hash), nunca en texto plano.

---

### [CRITICAL] XSS almacenado detectado (XSS-001)
**CWE:** CWE-79  
**URL:** `http://127.0.0.1:5000/product/1`  

**Evidencia:**
```
POST a http://127.0.0.1:5000/product/1 con payload <bopz8rc26s>STORED</bopz8rc26s>
El payload persiste y se refleja sin escapar en http://127.0.0.1:5000/product/1 para cualquier visitante posterior.
```

El input enviado por este formulario se guarda y luego se renderiza sin escapar para cualquier visitante de la página, no solo para quien lo envió. Es más grave que un reflejado porque no requiere que la víctima haga clic en un link malicioso.

**Remediación:** Escapar el contenido generado por usuarios al renderizar (quitar `|safe`) y sanitizar en el servidor antes de guardar (p. ej. con la librería `bleach`).

---

### [CRITICAL] XSS almacenado detectado (XSS-002)
**CWE:** CWE-79  
**URL:** `http://127.0.0.1:5000/product/2`  

**Evidencia:**
```
POST a http://127.0.0.1:5000/product/2 con payload <bopzs1c401>STORED</bopzs1c401>
El payload persiste y se refleja sin escapar en http://127.0.0.1:5000/product/2 para cualquier visitante posterior.
```

El input enviado por este formulario se guarda y luego se renderiza sin escapar para cualquier visitante de la página, no solo para quien lo envió. Es más grave que un reflejado porque no requiere que la víctima haga clic en un link malicioso.

**Remediación:** Escapar el contenido generado por usuarios al renderizar (quitar `|safe`) y sanitizar en el servidor antes de guardar (p. ej. con la librería `bleach`).

---

### [CRITICAL] XSS almacenado detectado (XSS-003)
**CWE:** CWE-79  
**URL:** `http://127.0.0.1:5000/product/3`  

**Evidencia:**
```
POST a http://127.0.0.1:5000/product/3 con payload <bopzzn84el>STORED</bopzzn84el>
El payload persiste y se refleja sin escapar en http://127.0.0.1:5000/product/3 para cualquier visitante posterior.
```

El input enviado por este formulario se guarda y luego se renderiza sin escapar para cualquier visitante de la página, no solo para quien lo envió. Es más grave que un reflejado porque no requiere que la víctima haga clic en un link malicioso.

**Remediación:** Escapar el contenido generado por usuarios al renderizar (quitar `|safe`) y sanitizar en el servidor antes de guardar (p. ej. con la librería `bleach`).

---

### [CRITICAL] XSS almacenado detectado (XSS-004)
**CWE:** CWE-79  
**URL:** `http://127.0.0.1:5000/product/4`  

**Evidencia:**
```
POST a http://127.0.0.1:5000/product/4 con payload <bopzp5x8tm>STORED</bopzp5x8tm>
El payload persiste y se refleja sin escapar en http://127.0.0.1:5000/product/4 para cualquier visitante posterior.
```

El input enviado por este formulario se guarda y luego se renderiza sin escapar para cualquier visitante de la página, no solo para quien lo envió. Es más grave que un reflejado porque no requiere que la víctima haga clic en un link malicioso.

**Remediación:** Escapar el contenido generado por usuarios al renderizar (quitar `|safe`) y sanitizar en el servidor antes de guardar (p. ej. con la librería `bleach`).

---

### [CRITICAL] XSS almacenado detectado (XSS-005)
**CWE:** CWE-79  
**URL:** `http://127.0.0.1:5000/product/5`  

**Evidencia:**
```
POST a http://127.0.0.1:5000/product/5 con payload <bopzgnaek4>STORED</bopzgnaek4>
El payload persiste y se refleja sin escapar en http://127.0.0.1:5000/product/5 para cualquier visitante posterior.
```

El input enviado por este formulario se guarda y luego se renderiza sin escapar para cualquier visitante de la página, no solo para quien lo envió. Es más grave que un reflejado porque no requiere que la víctima haga clic en un link malicioso.

**Remediación:** Escapar el contenido generado por usuarios al renderizar (quitar `|safe`) y sanitizar en el servidor antes de guardar (p. ej. con la librería `bleach`).

---

### [CRITICAL] XSS almacenado detectado (XSS-006)
**CWE:** CWE-79  
**URL:** `http://127.0.0.1:5000/product/6`  

**Evidencia:**
```
POST a http://127.0.0.1:5000/product/6 con payload <bopzgw07fk>STORED</bopzgw07fk>
El payload persiste y se refleja sin escapar en http://127.0.0.1:5000/product/6 para cualquier visitante posterior.
```

El input enviado por este formulario se guarda y luego se renderiza sin escapar para cualquier visitante de la página, no solo para quien lo envió. Es más grave que un reflejado porque no requiere que la víctima haga clic en un link malicioso.

**Remediación:** Escapar el contenido generado por usuarios al renderizar (quitar `|safe`) y sanitizar en el servidor antes de guardar (p. ej. con la librería `bleach`).

---

### [CRITICAL] XSS almacenado detectado (XSS-007)
**CWE:** CWE-79  
**URL:** `http://127.0.0.1:5000/product/7`  

**Evidencia:**
```
POST a http://127.0.0.1:5000/product/7 con payload <bopzrbweei>STORED</bopzrbweei>
El payload persiste y se refleja sin escapar en http://127.0.0.1:5000/product/7 para cualquier visitante posterior.
```

El input enviado por este formulario se guarda y luego se renderiza sin escapar para cualquier visitante de la página, no solo para quien lo envió. Es más grave que un reflejado porque no requiere que la víctima haga clic en un link malicioso.

**Remediación:** Escapar el contenido generado por usuarios al renderizar (quitar `|safe`) y sanitizar en el servidor antes de guardar (p. ej. con la librería `bleach`).

---

### [CRITICAL] XSS almacenado detectado (XSS-008)
**CWE:** CWE-79  
**URL:** `http://127.0.0.1:5000/product/8`  

**Evidencia:**
```
POST a http://127.0.0.1:5000/product/8 con payload <bopzs16cwf>STORED</bopzs16cwf>
El payload persiste y se refleja sin escapar en http://127.0.0.1:5000/product/8 para cualquier visitante posterior.
```

El input enviado por este formulario se guarda y luego se renderiza sin escapar para cualquier visitante de la página, no solo para quien lo envió. Es más grave que un reflejado porque no requiere que la víctima haga clic en un link malicioso.

**Remediación:** Escapar el contenido generado por usuarios al renderizar (quitar `|safe`) y sanitizar en el servidor antes de guardar (p. ej. con la librería `bleach`).

---

### [CRITICAL] XSS almacenado detectado (XSS-009)
**CWE:** CWE-79  
**URL:** `http://127.0.0.1:5000/product/9`  

**Evidencia:**
```
POST a http://127.0.0.1:5000/product/9 con payload <bopzfjykmo>STORED</bopzfjykmo>
El payload persiste y se refleja sin escapar en http://127.0.0.1:5000/product/9 para cualquier visitante posterior.
```

El input enviado por este formulario se guarda y luego se renderiza sin escapar para cualquier visitante de la página, no solo para quien lo envió. Es más grave que un reflejado porque no requiere que la víctima haga clic en un link malicioso.

**Remediación:** Escapar el contenido generado por usuarios al renderizar (quitar `|safe`) y sanitizar en el servidor antes de guardar (p. ej. con la librería `bleach`).

---

### [HIGH] Contraseña literal en el código (STATIC-SEC-002)
**CWE:** CWE-798  
**URL:** `repo:app.py:46`  

**Evidencia:**
```
Archivo: app.py  línea: 46
ADMIN_PASSWORD = ****REDACTED****
```

Variable con nombre relacionado a contraseña asignada con un valor literal en el código fuente.

**Remediación:** Cargar desde variable de entorno. Nunca almacenar contraseñas en texto plano ni en el código ni en la base de datos (usar bcrypt/argon2).

---

### [HIGH] Dependencia vulnerable: Flask==2.0.1 (STATIC-DEP-001)
**CWE:** CWE-1395  
**URL:** `repo:requirements.txt`  

**Evidencia:**
```
Paquete: Flask==2.0.1  (declarado en requirements.txt)
  [LOW] GHSA-68rp-wp8r-4726 — Flask session does not add `Vary: Cookie` header when accessed in some ways (CVE-2026-27205, PYSEC-2026-2151)
  [HIGH] GHSA-m2qf-hxjv-5gpq — Flask vulnerable to possible disclosure of permanent session cookie due to missing Vary: Cookie header (CVE-2023-30861, PYSEC-2023-62)
  [UNKNOWN] PYSEC-2023-62 — PYSEC-2023-62 (CVE-2023-30861, GHSA-m2qf-hxjv-5gpq)
  [UNKNOWN] PYSEC-2026-2151 — PYSEC-2026-2151 (CVE-2026-27205, GHSA-68rp-wp8r-4726)
```

La versión 2.0.1 de Flask tiene 4 vulnerabilidad(es) conocida(s) registrada(s) en OSV.dev / National Vulnerability Database.
CVEs: CVE-2026-27205, CVE-2023-30861

**Remediación:** Actualizar Flask a la versión más reciente estable (`pip install --upgrade Flask`) y anclar la versión en requirements.txt.

---

### [HIGH] Dependencia vulnerable: Werkzeug==2.0.1 (STATIC-DEP-002)
**CWE:** CWE-1395  
**URL:** `repo:requirements.txt`  

**Evidencia:**
```
Paquete: Werkzeug==2.0.1  (declarado en requirements.txt)
  [MODERATE] GHSA-29vq-49wr-vm6x —  Werkzeug safe_join() allows Windows special device names (CVE-2026-27199, PYSEC-2026-2320)
  [HIGH] GHSA-2g68-c3qc-8985 — Werkzeug debugger vulnerable to remote execution when interacting with attacker controlled domain (CVE-2024-34069, PYSEC-2026-2043)
  [MODERATE] GHSA-87hc-h4r5-73f7 —  Werkzeug safe_join() allows Windows special device names with compound extensions (CVE-2026-21860, PYSEC-2026-2044)
  [MODERATE] GHSA-f9vj-2wh5-fj8j — Werkzeug safe_join not safe on Windows (CVE-2024-49766, PYSEC-2026-2045)
  [MODERATE] GHSA-hgf8-39gv-g3f2 — Werkzeug safe_join() allows Windows special device names (CVE-2025-66221, PYSEC-2026-2046)
  [MODERATE] GHSA-hrfv-mqp8-q5rw — Werkzeug DoS: High resource usage when parsing multipart/form-data containing a large part with CR/LF character at the beginning (CVE-2023-46136, PYSEC-2023-221)
  [LOW] GHSA-px8h-6qxv-m22q — Incorrect parsing of nameless cookies leads to __Host- cookies bypass (CVE-2023-23934, PYSEC-2023-57)
  [MODERATE] GHSA-q34m-jh98-gwm2 — Werkzeug possible resource exhaustion when parsing file data in forms (CVE-2024-49767, PYSEC-2026-1860, PYSEC-2026-3417)
  [HIGH] GHSA-xg9f-g7g7-2323 — High resource usage when parsing multipart form data with many fields (CVE-2023-25577, PYSEC-2023-58)
  [UNKNOWN] PYSEC-2022-203 — PYSEC-2022-203 (CVE-2022-29361)
  [UNKNOWN] PYSEC-2023-221 — PYSEC-2023-221 (CVE-2023-46136, GHSA-hrfv-mqp8-q5rw)
  [UNKNOWN] PYSEC-2023-57 — PYSEC-2023-57 (CVE-2023-23934, GHSA-px8h-6qxv-m22q)
  [UNKNOWN] PYSEC-2023-58 — PYSEC-2023-58 (CVE-2023-25577, GHSA-xg9f-g7g7-2323)
  [UNKNOWN] PYSEC-2026-2043 — Werkzeug debugger vulnerable to remote execution when interacting with attacker controlled domain (CVE-2024-34069, GHSA-2g68-c3qc-8985)
  [UNKNOWN] PYSEC-2026-2044 —  Werkzeug safe_join() allows Windows special device names with compound extensions (CVE-2026-21860, GHSA-87hc-h4r5-73f7)
  [UNKNOWN] PYSEC-2026-2045 — Werkzeug safe_join not safe on Windows (CVE-2024-49766, GHSA-f9vj-2wh5-fj8j)
  [UNKNOWN] PYSEC-2026-2046 — Werkzeug safe_join() allows Windows special device names (CVE-2025-66221, GHSA-hgf8-39gv-g3f2)
  [UNKNOWN] PYSEC-2026-2320 — PYSEC-2026-2320 (CVE-2026-27199, GHSA-29vq-49wr-vm6x)
  [UNKNOWN] PYSEC-2026-3417 — Werkzeug possible resource exhaustion when parsing file data in forms (CVE-2024-49767, GHSA-q34m-jh98-gwm2, PYSEC-2026-1860)
```

La versión 2.0.1 de Werkzeug tiene 19 vulnerabilidad(es) conocida(s) registrada(s) en OSV.dev / National Vulnerability Database.
CVEs: CVE-2026-27199, CVE-2024-34069, CVE-2026-21860, CVE-2024-49766, CVE-2025-66221, CVE-2023-46136, CVE-2023-23934, CVE-2024-49767, CVE-2023-25577, CVE-2022-29361

**Remediación:** Actualizar Werkzeug a la versión más reciente estable (`pip install --upgrade Werkzeug`) y anclar la versión en requirements.txt.

---

### [MEDIUM] Dependencia vulnerable: Jinja2==3.0.1 (STATIC-DEP-003)
**CWE:** CWE-1395  
**URL:** `repo:requirements.txt`  

**Evidencia:**
```
Paquete: Jinja2==3.0.1  (declarado en requirements.txt)
  [MODERATE] GHSA-cpwx-vrp4-4pq7 — Jinja2 vulnerable to sandbox breakout through attr filter selecting format method (CVE-2025-27516, PYSEC-2026-1471)
  [MODERATE] GHSA-gmj6-6f8f-6699 — Jinja has a sandbox breakout through malicious filenames (CVE-2024-56201, PYSEC-2026-1472)
  [MODERATE] GHSA-h5c8-rqwp-cp95 — Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter (CVE-2024-22195, PYSEC-2026-1473)
  [MODERATE] GHSA-h75v-3vvj-5mfj — Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter (CVE-2024-34064, PYSEC-2026-1474)
  [MODERATE] GHSA-q2x7-8rv6-6q7h — Jinja has a sandbox breakout through indirect reference to format method (CVE-2024-56326, PYSEC-2026-1475)
  [UNKNOWN] PYSEC-2026-1471 — Jinja2 vulnerable to sandbox breakout through attr filter selecting format method (CVE-2025-27516, GHSA-cpwx-vrp4-4pq7)
  [UNKNOWN] PYSEC-2026-1472 — Jinja has a sandbox breakout through malicious filenames (CVE-2024-56201, GHSA-gmj6-6f8f-6699)
  [UNKNOWN] PYSEC-2026-1473 — Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter (CVE-2024-22195, GHSA-h5c8-rqwp-cp95)
  [UNKNOWN] PYSEC-2026-1474 — Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter (CVE-2024-34064, GHSA-h75v-3vvj-5mfj)
  [UNKNOWN] PYSEC-2026-1475 — Jinja has a sandbox breakout through indirect reference to format method (CVE-2024-56326, GHSA-q2x7-8rv6-6q7h)
```

La versión 3.0.1 de Jinja2 tiene 10 vulnerabilidad(es) conocida(s) registrada(s) en OSV.dev / National Vulnerability Database.
CVEs: CVE-2025-27516, CVE-2024-56201, CVE-2024-22195, CVE-2024-34064, CVE-2024-56326

**Remediación:** Actualizar Jinja2 a la versión más reciente estable (`pip install --upgrade Jinja2`) y anclar la versión en requirements.txt.

---

### [MEDIUM] Dependencia vulnerable: click==8.0.1 (STATIC-DEP-004)
**CWE:** CWE-1395  
**URL:** `repo:requirements.txt`  

**Evidencia:**
```
Paquete: click==8.0.1  (declarado en requirements.txt)
  [UNKNOWN] PYSEC-2026-2132 — PYSEC-2026-2132 (CVE-2026-7246, GHSA-47fr-3ffg-hgmw)
```

La versión 8.0.1 de click tiene 1 vulnerabilidad(es) conocida(s) registrada(s) en OSV.dev / National Vulnerability Database.
CVEs: CVE-2026-7246

**Remediación:** Actualizar click a la versión más reciente estable (`pip install --upgrade click`) y anclar la versión en requirements.txt.

---

### [MEDIUM] Header de seguridad ausente: Content-Security-Policy (HDR-001)
**CWE:** CWE-693  
**URL:** `http://127.0.0.1:5000`  

**Evidencia:**
```
La respuesta no incluye el header 'Content-Security-Policy'
```

Mitiga XSS restringiendo qué scripts/recursos puede cargar el navegador.

**Remediación:** Configurar el servidor/framework para enviar 'Content-Security-Policy' en todas las respuestas (en Flask: flask-talisman lo automatiza).

---

### [MEDIUM] Header de seguridad ausente: Strict-Transport-Security (HDR-004)
**CWE:** CWE-693  
**URL:** `http://127.0.0.1:5000`  

**Evidencia:**
```
La respuesta no incluye el header 'Strict-Transport-Security'
```

Fuerza HTTPS y previene downgrade/sslstrip en redes hostiles.

**Remediación:** Configurar el servidor/framework para enviar 'Strict-Transport-Security' en todas las respuestas (en Flask: flask-talisman lo automatiza).

---

### [MEDIUM] Formulario POST sin token CSRF (http://127.0.0.1:5000/login) (CSRF-001)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/login`  

**Evidencia:**
```
Campos del formulario: ['username', 'password']
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [MEDIUM] Formulario POST sin token CSRF (http://127.0.0.1:5000/cart/add/1) (CSRF-003)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/cart/add/1`  

**Evidencia:**
```
Campos del formulario: []
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [MEDIUM] Formulario POST sin token CSRF (http://127.0.0.1:5000/cart/add/2) (CSRF-005)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/cart/add/2`  

**Evidencia:**
```
Campos del formulario: []
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [MEDIUM] Formulario POST sin token CSRF (http://127.0.0.1:5000/cart/add/3) (CSRF-007)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/cart/add/3`  

**Evidencia:**
```
Campos del formulario: []
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [MEDIUM] Formulario POST sin token CSRF (http://127.0.0.1:5000/cart/add/4) (CSRF-009)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/cart/add/4`  

**Evidencia:**
```
Campos del formulario: []
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [MEDIUM] Formulario POST sin token CSRF (http://127.0.0.1:5000/cart/add/5) (CSRF-011)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/cart/add/5`  

**Evidencia:**
```
Campos del formulario: []
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [MEDIUM] Formulario POST sin token CSRF (http://127.0.0.1:5000/cart/add/6) (CSRF-013)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/cart/add/6`  

**Evidencia:**
```
Campos del formulario: []
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [MEDIUM] Formulario POST sin token CSRF (http://127.0.0.1:5000/cart/add/7) (CSRF-015)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/cart/add/7`  

**Evidencia:**
```
Campos del formulario: []
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [MEDIUM] Formulario POST sin token CSRF (http://127.0.0.1:5000/cart/add/8) (CSRF-017)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/cart/add/8`  

**Evidencia:**
```
Campos del formulario: []
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [MEDIUM] Formulario POST sin token CSRF (http://127.0.0.1:5000/cart/add/9) (CSRF-019)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/cart/add/9`  

**Evidencia:**
```
Campos del formulario: []
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [LOW] Header de seguridad ausente: X-Frame-Options (HDR-002)
**CWE:** CWE-693  
**URL:** `http://127.0.0.1:5000`  

**Evidencia:**
```
La respuesta no incluye el header 'X-Frame-Options'
```

Previene clickjacking evitando que el sitio se cargue dentro de un <iframe>.

**Remediación:** Configurar el servidor/framework para enviar 'X-Frame-Options' en todas las respuestas (en Flask: flask-talisman lo automatiza).

---

### [LOW] Header de seguridad ausente: X-Content-Type-Options (HDR-003)
**CWE:** CWE-693  
**URL:** `http://127.0.0.1:5000`  

**Evidencia:**
```
La respuesta no incluye el header 'X-Content-Type-Options'
```

Evita que el navegador adivine (sniffing) el tipo MIME de un recurso.

**Remediación:** Configurar el servidor/framework para enviar 'X-Content-Type-Options' en todas las respuestas (en Flask: flask-talisman lo automatiza).

---

### [LOW] Header de seguridad ausente: Referrer-Policy (HDR-005)
**CWE:** CWE-693  
**URL:** `http://127.0.0.1:5000`  

**Evidencia:**
```
La respuesta no incluye el header 'Referrer-Policy'
```

Controla qué URL se filtra en el header Referer hacia otros sitios.

**Remediación:** Configurar el servidor/framework para enviar 'Referrer-Policy' en todas las respuestas (en Flask: flask-talisman lo automatiza).

---

### [LOW] Banner de servidor revela versión exacta (HDR-006)
**CWE:** CWE-200  
**URL:** `http://127.0.0.1:5000`  

**Evidencia:**
```
Header Server: Werkzeug/3.1.5 Python/3.13.12
```

Revelar la versión exacta del servidor/framework facilita que un atacante busque CVEs específicos para esa versión.

**Remediación:** Ocultar o genericizar el header Server en producción.

---

### [LOW] Formulario POST sin token CSRF (http://127.0.0.1:5000/register) (CSRF-002)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/register`  

**Evidencia:**
```
Campos del formulario: ['username', 'password']
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [LOW] Formulario POST sin token CSRF (http://127.0.0.1:5000/product/1) (CSRF-004)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/product/1`  

**Evidencia:**
```
Campos del formulario: ['author', 'comment']
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [LOW] Formulario POST sin token CSRF (http://127.0.0.1:5000/product/2) (CSRF-006)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/product/2`  

**Evidencia:**
```
Campos del formulario: ['author', 'comment']
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [LOW] Formulario POST sin token CSRF (http://127.0.0.1:5000/product/3) (CSRF-008)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/product/3`  

**Evidencia:**
```
Campos del formulario: ['author', 'comment']
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [LOW] Formulario POST sin token CSRF (http://127.0.0.1:5000/product/4) (CSRF-010)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/product/4`  

**Evidencia:**
```
Campos del formulario: ['author', 'comment']
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [LOW] Formulario POST sin token CSRF (http://127.0.0.1:5000/product/5) (CSRF-012)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/product/5`  

**Evidencia:**
```
Campos del formulario: ['author', 'comment']
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [LOW] Formulario POST sin token CSRF (http://127.0.0.1:5000/product/6) (CSRF-014)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/product/6`  

**Evidencia:**
```
Campos del formulario: ['author', 'comment']
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [LOW] Formulario POST sin token CSRF (http://127.0.0.1:5000/product/7) (CSRF-016)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/product/7`  

**Evidencia:**
```
Campos del formulario: ['author', 'comment']
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [LOW] Formulario POST sin token CSRF (http://127.0.0.1:5000/product/8) (CSRF-018)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/product/8`  

**Evidencia:**
```
Campos del formulario: ['author', 'comment']
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---

### [LOW] Formulario POST sin token CSRF (http://127.0.0.1:5000/product/9) (CSRF-020)
**CWE:** CWE-352  
**URL:** `http://127.0.0.1:5000/product/9`  

**Evidencia:**
```
Campos del formulario: ['author', 'comment']
Ninguno coincide con patrones típicos de token CSRF (csrf_token, _token, authenticity_token, csrfmiddlewaretoken...)
```

Un sitio malicioso podría auto-enviar este formulario desde el navegador de una víctima autenticada (con un <form> oculto que se auto-envía), ejecutando la acción en su nombre sin que lo note.

**Remediación:** Agregar un token CSRF único por sesión (Flask-WTF lo genera automáticamente) y validarlo en el backend antes de procesar el POST. Alternativa/complemento: SameSite=Strict en la cookie de sesión.

---
