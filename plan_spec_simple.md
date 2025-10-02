# 📑 Especificación Simplificada: Plan de Acción (Dry-Run + Apply)

## 🎯 Objetivo
Diseñar un mecanismo que, a partir de los duplicados encontrados, genere un **plan de acción** que luego se pueda:
- **Revisar sin ejecutar** (`dry-run`).
- **Aplicar de verdad** (`apply`).

---

## 🧩 Componentes principales

1. **Plan de acción (`plan.json`)**  
   - Archivo JSON que lista:
     - Grupos de duplicados.
     - Qué archivo se conserva (survivor).
     - Qué hacer con los demás (mover a cuarentena o borrar).

2. **Modo Dry-Run**  
   - Simula la ejecución del plan.  
   - No toca los archivos.  
   - Devuelve un resumen: cuántos se moverían, borrarían, omitirían.

3. **Modo Apply**  
   - Ejecuta las acciones del plan.  
   - Mueve archivos a una carpeta de cuarentena o los borra (si confirmaste).  
   - Genera un archivo `undo.json` para revertir los movimientos.

---

## 📦 Estructura del Plan

Ejemplo de `plan.json`:

```json
{
  "plan_id": "123e4567-e89b-12d3-a456-426614174000",
  "created_at": "2025-09-26T20:30:00Z",
  "policy": "keep_newest",
  "action": "move_to_quarantine",
  "quarantine_dir": ".quarantine",
  "groups": [
    {
      "group_id": "hash:abcd1234",
      "survivor": "C:/Users/Carla/docs/original.pdf",
      "duplicates": [
        {
          "path": "C:/Users/Carla/docs/copia.pdf",
          "proposed": {
            "action": "move",
            "to": ".quarantine/C_/Users/Carla/docs/copia.pdf"
          }
        }
      ]
    }
  ],
  "stats": {
    "groups": 1,
    "files_to_act": 1,
    "wasted_size_bytes": 123456
  }
}
```

---

## ⚙️ Políticas y acciones

- **Selección de Survivor**  
  - `keep_first`: el primero que aparezca.  
  - `keep_oldest`: el más viejo.  
  - `keep_newest`: el más nuevo.  

- **Acciones sobre duplicados**  
  - `move_to_quarantine`: mover a `.quarantine`.  
  - `delete`: borrar (sólo si confirmás).  

- **Colisiones (si el destino ya existe)**  
  - `rename`: agregar sufijo `__dup1`, `__dup2`.  
  - `skip`: saltar el archivo.  
  - `overwrite`: reemplazar (menos seguro).

---

## 🚦 Flujo de uso

1. **Detectar duplicados**  
   - Usar tu módulo normal (`find_duplicates_by_hash`, etc.).  

2. **Generar Plan**  
   - Crear JSON con grupos, survivor y acciones propuestas.  
   - Guardarlo en `plan.json`.  

3. **Dry-Run**  
   - Leer `plan.json`.  
   - Mostrar resumen:  
     ```json
     { "moved": 10, "deleted": 0, "skipped": 2, "errors": 0 }
     ```

4. **Apply**  
   - Ejecutar las acciones reales.  
   - Si `move_to_quarantine`, crear las carpetas necesarias y mover archivos.  
   - Si `delete`, verificar que `confirm_delete=true`.  
   - Generar `undo.json` con todas las acciones realizadas.

---

## 🛡️ Seguridad básica

- No borrar nada sin confirmación.  
- Si un archivo ya no existe al aplicar, marcar como `skipped`.  
- Si hubo error de permisos o disco, registrar y continuar con los demás.  
- Conservar estructura espejo dentro de `.quarantine`.  

---

## ✅ Resultado esperado

- **Dry-Run** y **Apply** entregan siempre un **resumen de acciones** (`moved`, `deleted`, `skipped`, `errors`).  
- El plan (`plan.json`) es auto-contenible: cualquiera puede revisarlo antes de aplicar.  
- Con `undo.json` es posible revertir los movimientos (volver los archivos a su lugar original).  
