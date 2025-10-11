# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Estructura del Proyecto

Este es **Duply**, un detector de archivos duplicados con implementación full-stack:

- `modulos/duplicados/duplicate_detector.py`: Biblioteca principal en Python que expone la clase `DuplicateDetector` con múltiples estrategias de detección (hash, name, size, hybrid)
- `modulos/duplicados/backend/`: API REST con FastAPI que envuelve la biblioteca detectora
- `modulos/duplicados/frontend/`: Interfaz HTML estática para la aplicación web

La biblioteca soporta características avanzadas incluyendo planes de acción (modos dry-run y apply), estrategias de resolución de colisiones, y logging estructurado en formato NDJSON.

## Configuración de Desarrollo

### Entorno Virtual

1. Crear entorno virtual desde la raíz del repositorio:

   ```bash
   python -m venv modulos/duplicados/.venv
   ```

2. Activar en Windows (PowerShell):

   ```powershell
   modulos/duplicados\.venv\Scripts\Activate.ps1
   ```

3. Instalar dependencias del backend:

   ```bash
   pip install -r modulos/duplicados/backend/requirements.txt
   ```

### Ejecutar la Aplicación

**CLI (Biblioteca Standalone)**:

```bash
python modulos/duplicados/duplicate_detector.py <directorio> [método]
```

- Métodos: `hash`, `name`, `size`, `hybrid` (por defecto: `hybrid`)
- Salida: `duplicados_<método>_<timestamp>.json` en el directorio actual

**Backend API**:
```bash
cd modulos/duplicados
uvicorn backend.main:app --reload
```
- Servidor: `http://localhost:8000`
- Frontend integrado: `http://localhost:8000/` (sirve automáticamente `frontend/index.html`)
- Documentación API: `http://localhost:8000/docs`

**Frontend (alternativo, servidor estático independiente)**:
```bash
python -m http.server 5500 --directory modulos/duplicados/frontend
```
- Interfaz: `http://localhost:5500/index.html`

## Arquitectura Central

### Estrategias de Detección

La clase `DuplicateDetector` provee cuatro métodos de detección:

1. **`find_duplicates_by_hash()`**: Detección basada en contenido usando MD5/SHA256
2. **`find_duplicates_by_name()`**: Detección basada en nombre de archivo (case-sensitive opcional)
3. **`find_duplicates_by_size()`**: Detección basada en tamaño (rápida pero menos precisa)
4. **`find_duplicates_hybrid()`**: Enfoque de dos fases—primero agrupa por tamaño, luego verifica con hash (recomendado para directorios grandes)

Todos los métodos retornan `Dict[str, List[str]]` mapeando identificadores (hash/name/size) a rutas de archivos.

### Sistema de Planes de Acción

La biblioteca implementa un flujo basado en planes para operaciones seguras sobre archivos:

1. **Generar Plan** (`generate_action_plan()`):
   - Crea `plan.json` describiendo las acciones propuestas
   - Políticas de superviviente: `keep_first`, `keep_oldest`, `keep_newest`
   - Acciones: `move_to_quarantine`, `delete`
   - Estrategias de colisión: `rename`, `skip`, `overwrite`

2. **Dry Run** (`dry_run_plan()`):
   - Simula la ejecución del plan sin tocar el sistema de archivos
   - Retorna resumen: `moved`, `deleted`, `skipped`, `errors`, `missing`

3. **Aplicar Plan** (`apply_plan()`):
   - Ejecuta las acciones (requiere `confirm_delete=True` para borrados)
   - Genera `undo.json` para revertir operaciones de movimiento
   - Preserva la estructura de directorios en carpeta `.quarantine/`

### Infraestructura de Logging

Los logs siguen formato NDJSON (un objeto JSON por línea) con salidas duales:

- **Logs NDJSON**: `logs/duplicate-detector.log`, `logs/duplicate-detector.api.log` (legibles por máquina)
- **Logs texto**: `logs/duplicate-detector.txt`, `logs/duplicate-detector.api.txt` (legibles por humanos)
- **Rotación**: Tamaño máximo 5MB, 5 backups para logs generales, 3 para logs de API
- **Sobrescribir directorio de logs**: Configurar variable de entorno `DUPLY_LOG_DIR`

Campos clave de logs: `scan_id` (UUID para correlación), `component` (library/api/cli), `event` (nombre estructurado de evento), `timestamp` (ISO-8601 UTC).

Consultar `modulos/duplicados/3_espec_log.md` para especificación completa de logging.

### Endpoints de la API

- `GET /`: Sirve la interfaz web frontend (desde `frontend/index.html`)
- `POST /scan`: Ejecutar escaneo de duplicados (parámetros: `path`, `method`, `extensions`, `recursive`)
- `GET /stats`: Obtener estadísticas del último escaneo
- `GET /export?format=json|csv`: Descargar resultados del último escaneo (archivos guardados en `backend/exports/`)
- `GET /health`: Endpoint de health check

Los escaneos se persisten en `backend/data/last_scan.json` para reutilización por otras características.

## Convenciones de Código

- **Estilo**: PEP 8 (indentación de 4 espacios, límite de línea de 88 caracteres recomendado)
- **Nombrado**: `snake_case` para funciones/variables, `PascalCase` para clases, minúsculas con guiones bajos para módulos
- **Type hints**: Requeridos para APIs públicas
- **Docstrings**: Explicar intención y casos borde
- **Normalización de extensiones**: La API y biblioteca aceptan tanto `.pdf` como `pdf` (internamente normalizadas con punto inicial)

## Patrones Comunes

### Manejo de Rutas
- Usar `pathlib.Path` consistentemente a lo largo del código
- Todas las rutas se resuelven y normalizan antes de procesarse
- Las letras de unidad de Windows se sanitizan al construir rutas de cuarentena (ej: `C:` → `C_`)

### Manejo de Errores
- Distinguir entre errores recuperables (logueados como WARNING, el escaneo continúa) y errores fatales (logueados como ERROR, la operación falla)
- Errores de permisos y archivos faltantes se loguean pero no detienen los escaneos
- Usar logging estructurado de excepciones con campos `exception_type` y `exception_msg`

### Testing
- Aumentar verbosidad para desarrollo: `$env:PYTHONLOGLEVEL = "INFO"` (PowerShell)
- O ajustar nivel del logger en código: `logger.setLevel(logging.DEBUG)`
- Las salidas del CLI se almacenan como JSON para verificación programática

## Trabajar con Planes

Al modificar código relacionado con planes:
- Los planes son auto-contenidos: incluyen `context` del escaneo original
- La resolución de colisiones ocurre tanto en generación (preview) como en apply (real)
- Los archivos undo mapean rutas de cuarentena de vuelta a ubicaciones originales
- Los archivos faltantes durante apply se cuentan separadamente en el resumen (campo `missing`)

Consultar `modulos/duplicados/plan_spec_simple.md` para especificación detallada de planes.

## Contexto del Repositorio

- **Idioma primario**: Español (documentación, comentarios en especificaciones)
- **Idioma de código**: Inglés (nombres de variables, docstrings, comentarios de código)
- **Estilo de commits**: Conventional Commits recomendado (`feat:`, `fix:`, `docs:`) con alcances descriptivos
