
# Especificación de Logging para **Duplicate Detector** (v1.0)

> Documento de referencia para instrumentar y consumir logs del sistema de detección de archivos duplicados.
> Formato: **JSON por línea (NDJSON)**, orientado a ingestión en ELK/Loki/Datadog/CloudWatch.

---

## 1. Objetivo

Establecer un estándar único de **formato, campos, niveles, eventos y políticas** de persistencia para los logs generados por:
- Biblioteca: `duplicate_detector.py` (métodos de escaneo, comparación y exportación).
- CLI: ejecución directa del módulo.
- API: servicio web (FastAPI/Flask) que exponga el detector.

---

## 2. Formato de registro

- **Formato:** JSON **una línea por evento** (NDJSON). No se permiten saltos de línea dentro del JSON.
- **Codificación:** UTF-8.
- **Zona horaria:** UTC (sufijo `Z`).
- **Separador:** nueva línea (`\n`).

Ejemplo mínimo:

```json
{"timestamp":"2025-09-26T23:18:20Z","level":"INFO","event":"scan_finished","scan_id":"a3c2-...","message":"Escaneo completado"}
```

---

## 3. Niveles

- `DEBUG`: detalle de bajo nivel (mediciones por archivo, buckets, etc.). Desactivado por defecto.
- `INFO`: hitos del flujo y métricas resumidas.
- `WARNING`: errores recuperables (permisos, archivo corrupto, no-regular file).
- `ERROR`: errores no recuperables en una operación (fallo de exportación, path raíz inexistente).
- `CRITICAL`: caídas del proceso o fallas que imposibilitan continuar.

---

## 4. Esquema de campos (JSON)

| Campo | Tipo | Obligatorio | Descripción |
|---|---|:---:|---|
| `timestamp` | string (ISO8601 UTC) | ✔ | Momento del evento, p.ej. `2025-09-26T23:18:20Z` |
| `level` | string | ✔ | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` |
| `event` | string | ✔ | Nombre corto y estable del evento (ver §7) |
| `message` | string | ✔ | Mensaje humano-legible |
| `scan_id` | string (UUID) | ✔ | Correlación de todos los logs de un mismo escaneo |
| `component` | string | ✔ | `cli` \| `library` \| `api` |
| `version` | string | ✔ | Versión del módulo/aplicación |
| `env` | string | ✔ | `dev` \| `staging` \| `prod` |
| `root_dir` | string | ✔ | Directorio objetivo del escaneo (ver privacidad §9) |
| `recursive` | boolean | ✔ | Búsqueda recursiva |
| `extensions` | array[string] \| null | ✖ | Filtro de extensiones |
| `hash_method` | string | ✖ | `md5` \| `sha256` |
| `chunk_size` | integer | ✖ | Tamaño de lectura en bytes |
| `files_processed` | integer | ✖ | Archivos leídos hasta el momento |
| `groups_found` | integer | ✖ | Cantidad de grupos de duplicados detectados |
| `total_duplicate_files` | integer | ✖ | Archivos duplicados (suma de grupos) |
| `wasted_size_bytes` | integer | ✖ | Tamaño total desperdiciado en bytes |
| `duration_ms` | integer | ✖ | Duración de la operación en milisegundos |
| `request_id` | string | ✖ | Correlación por request HTTP (API) |
| `route` | string | ✖ | Ruta llamada (API) |
| `status_code` | integer | ✖ | Código HTTP de respuesta (API) |
| `file` | string | ✖ | Ruta de archivo individual afectado |
| `size` | integer | ✖ | Tamaño de archivo en bytes |
| `exception_type` | string | ✖ | Clase de excepción |
| `exception_msg` | string | ✖ | Mensaje de excepción (sanitizado) |

### 4.1. JSON Schema (referencia)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "DuplicateDetectorLog",
  "type": "object",
  "required": ["timestamp","level","event","message","scan_id","component","version","env","root_dir","recursive"],
  "properties": {
    "timestamp": {"type":"string","format":"date-time"},
    "level": {"type":"string","enum":["DEBUG","INFO","WARNING","ERROR","CRITICAL"]},
    "event": {"type":"string","minLength":1},
    "message": {"type":"string"},
    "scan_id": {"type":"string","minLength":4},
    "component": {"type":"string","enum":["cli","library","api"]},
    "version": {"type":"string"},
    "env": {"type":"string","enum":["dev","staging","prod"]},
    "root_dir": {"type":"string"},
    "recursive": {"type":"boolean"},
    "extensions": {"type":["array","null"], "items":{"type":"string"}},
    "hash_method": {"type":"string","enum":["md5","sha256"]},
    "chunk_size": {"type":"integer","minimum":1},
    "files_processed": {"type":"integer","minimum":0},
    "groups_found": {"type":"integer","minimum":0},
    "total_duplicate_files": {"type":"integer","minimum":0},
    "wasted_size_bytes": {"type":"integer","minimum":0},
    "duration_ms": {"type":"integer","minimum":0},
    "request_id": {"type":"string"},
    "route": {"type":"string"},
    "status_code": {"type":"integer","minimum":100,"maximum":599},
    "file": {"type":"string"},
    "size": {"type":"integer","minimum":0},
    "exception_type": {"type":"string"},
    "exception_msg": {"type":"string"}
  },
  "additionalProperties": true
}
```

---

## 5. Identificadores de correlación

- `scan_id` (UUID): generado **por escaneo**. Requerido en todos los eventos del flujo de escaneo.
- `request_id` (UUID): generado **por request HTTP** (middleware API). Se incluye en eventos del componente `api`.
- Ambos IDs permiten seguir extremo a extremo: **API → Librería → Exportación**.

---

## 6. Política de persistencia y rotación

- **Desarrollo**: consola (stdout) + archivo con rotación diaria (`backupCount=7`).
- **Producción (contenedores)**: **stdout** como canal principal (recomendado). El agente del cluster recolecta y envía.
- **Producción (bare metal)**: archivo rotativo por tamaño (p.ej. 50 MB, `backupCount=10`).

Nombres sugeridos:
- `duplicate-detector.log` (canal consolidado)
- `duplicate-detector.api.log` (si se separa por componente)

---

## 7. Catálogo de eventos

### 7.1 Flujo de escaneo (component=`library`)

- `scan_started` (INFO) — inicio de un escaneo. Campos: `hash_method`, `chunk_size`.
- `directory_walk_progress` (INFO) — progreso cada N archivos. Campos: `files_processed`, `duration_ms`.
- `size_bucket_detected` (DEBUG) — modo híbrido: detecta bucket de tamaño con candidatos >1. Campos: `size`, `files_processed`.
- `hash_computed` (DEBUG) — hash calculado para archivo candidato (opcional). Campos: `file`, `size`.
- `scan_finished` (INFO) — fin del escaneo. Campos: `files_processed`, `groups_found`, `total_duplicate_files`, `wasted_size_bytes`, `duration_ms`.

### 7.2 Incidencias de archivo

- `file_skipped_permission` (WARNING) — sin permisos para leer. Campos: `file`.
- `file_skipped_not_file` (WARNING) — path no es archivo regular. Campos: `file`.
- `file_error_hash` (WARNING/ERROR) — error calculando hash. Campos: `file`, `exception_type`.

### 7.3 Comparación de directorios

- `dir_compare_started` (INFO) — inicio de comparación entre `dir1` y `dir2`.
- `dir_compare_finished` (INFO) — fin con `stats.total_dir1`, `stats.total_dir2`, `stats.common_items`.

### 7.4 Exportación

- `export_completed` (INFO) — export exitosa. Campos: `format`, `output_file`, `bytes_written`, `duration_ms`.
- `export_failed` (ERROR) — export fallida. Campos: `format`, `output_file`, `exception_type`.

### 7.5 API (component=`api`)

- `api_request` (INFO) — entrada a endpoint. Campos: `request_id`, `route`, `method`, `client_ip` (siempre sanitizado), `params_hash` (sin PII).
- `api_response` (INFO) — respuesta del endpoint. Campos: `request_id`, `route`, `status_code`, `duration_ms`.

---

## 8. Privacidad y seguridad

- No registrar **contenido** de archivos ni rutas sensibles en entornos compartidos.
- En producción, considerar **enmascarar** parte de `root_dir` y `file` o registrar rutas **relativas** al directorio base.
- `exception_msg` debe ser sanitizado (sin secretos/token/PII).
- Evitar registrar **hashes completos** de archivos en `DEBUG` en ambientes productivos; preferir `hash_prefix` (8–12 caracteres).

---

## 9. Reglas de calidad

- Cada línea debe ser un JSON válido. Evitar concatenaciones o logs multilínea.
- Incluir `scan_id` en todos los eventos del flujo de escaneo.
- Respetar las mayúsculas de `level`.
- Usar `event` de este catálogo; si se crean nuevos, documentarlos y versionar el presente documento.

---

## 10. Ejemplos de eventos

```json
{"timestamp":"2025-09-26T23:18:00Z","level":"INFO","event":"scan_started","component":"library","version":"1.0.0","env":"dev","scan_id":"a3c2","root_dir":"/data","recursive":true,"extensions":[".pdf",".jpg"],"hash_method":"md5","chunk_size":8192,"message":"Escaneo iniciado"}
{"timestamp":"2025-09-26T23:18:05Z","level":"INFO","event":"directory_walk_progress","component":"library","version":"1.0.0","env":"dev","scan_id":"a3c2","root_dir":"/data","recursive":true,"files_processed":500,"duration_ms":432,"message":"Progreso"}
{"timestamp":"2025-09-26T23:18:06Z","level":"WARNING","event":"file_skipped_permission","component":"library","version":"1.0.0","env":"dev","scan_id":"a3c2","root_dir":"/data","recursive":true,"file":"/data/privado/secret.docx","message":"Archivo omitido por permisos"}
{"timestamp":"2025-09-26T23:18:20Z","level":"INFO","event":"scan_finished","component":"library","version":"1.0.0","env":"dev","scan_id":"a3c2","root_dir":"/data","recursive":true,"groups_found":42,"total_duplicate_files":103,"wasted_size_bytes":734003200,"duration_ms":15234,"message":"Escaneo completado"}
{"timestamp":"2025-09-26T23:18:21Z","level":"INFO","event":"export_completed","component":"library","version":"1.0.0","env":"dev","scan_id":"a3c2","root_dir":"/data","recursive":true,"format":"json","output_file":"duplicados_hybrid_20250926_231820.json","bytes_written":123456,"duration_ms":88,"message":"Export ok"}
```

---

## 11. Integración (pautas)

- Logger raíz del módulo: nombre **`duplicate_detector`**.
- Formateador JSON por línea en **stdout** y (opcional) archivo con rotación.
- Inyectar contexto fijo con `LoggerAdapter` o filtros: `scan_id`, `root_dir`, `hash_method`, `chunk_size`, `recursive`, `extensions`.
- Middleware en API para `request_id` y timings por ruta.

---

## 12. Mapeo sugerido de eventos ↔ código

- `find_duplicates_by_hash/name/size/hybrid` → `scan_started`, `directory_walk_progress`, `scan_finished`, incidencias de archivo.
- `compare_directories` → `dir_compare_*` + `stats.*`.
- `export_results` → `export_*`.
- CLI (`__main__`) → generación de `scan_id`, medición total, resumen final.

---

## 13. Versionado del documento

- v1.0 (2025-09-26): versión inicial.
- Cambios futuros deben actualizar **`version`** en los registros y en este documento.

---

## 14. Anexos

### 14.1 Convenciones de nombres

- `event`: snake_case, estable en el tiempo.
- `component`: uno de `cli` / `library` / `api`.

### 14.2 Métricas recomendadas (exportar a observabilidad)

- Tasa de archivos procesados (`files_processed / duration_ms`).
- Tiempo medio por bucket (modo híbrido).
- Ahorro total estimado (`wasted_size_bytes`).

---

Fin de la especificación.
