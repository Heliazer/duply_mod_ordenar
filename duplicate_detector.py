#!/usr/bin/env python3
"""
MÓDULO DETECTOR DE ARCHIVOS DUPLICADOS
=====================================
Módulo reutilizable para detectar archivos duplicados usando diferentes técnicas:
- Hash MD5/SHA256 del contenido completo
- Comparación por nombre de archivo
- Comparación por tamaño de archivo
- Métodos híbridos para mayor eficiencia

Este módulo puede ser importado desde cualquier programa para utilizar
las técnicas de detección de duplicados desarrolladas en este proyecto.

Uso básico:
    from duplicate_detector import DuplicateDetector

    detector = DuplicateDetector()
    duplicados = detector.find_duplicates('/ruta/a/archivos')

Autor: Generado por Claude Code
Fecha: 2025-09-21
"""

import os
import hashlib
import json
import csv
from pathlib import Path
from typing import Dict, List, Tuple, Set, Optional, Union
from datetime import datetime
from collections import defaultdict
import logging


class DuplicateDetector:
    """
    Clase principal para detección de archivos duplicados.

    Proporciona múltiples métodos para identificar duplicados:
    - Por hash del contenido (MD5, SHA256)
    - Por nombre de archivo
    - Por tamaño de archivo
    - Métodos híbridos para optimización
    """

    def __init__(self, hash_method: str = 'md5', chunk_size: int = 8192):
        """
        Inicializa el detector de duplicados.

        Args:
            hash_method: Método de hash a usar ('md5' o 'sha256')
            chunk_size: Tamaño del chunk para lectura de archivos en bytes
        """
        self.hash_method = hash_method.lower()
        self.chunk_size = chunk_size
        self.logger = self._setup_logger()

        if self.hash_method not in ['md5', 'sha256']:
            raise ValueError("hash_method debe ser 'md5' o 'sha256'")

    def _setup_logger(self) -> logging.Logger:
        """Configura el sistema de logging."""
        logger = logging.getLogger('duplicate_detector')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def calculate_file_hash(self, file_path: Union[str, Path]) -> str:
        """
        Calcula el hash de un archivo.

        Args:
            file_path: Ruta al archivo

        Returns:
            Hash del archivo en hexadecimal

        Raises:
            FileNotFoundError: Si el archivo no existe
            PermissionError: Si no hay permisos para leer el archivo
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

        if not file_path.is_file():
            raise ValueError(f"La ruta no corresponde a un archivo: {file_path}")

        hash_obj = hashlib.md5() if self.hash_method == 'md5' else hashlib.sha256()

        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(self.chunk_size):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except PermissionError:
            raise PermissionError(f"Sin permisos para leer: {file_path}")
        except Exception as e:
            self.logger.error(f"Error calculando hash de {file_path}: {e}")
            raise

    def find_duplicates_by_hash(self, directory: Union[str, Path],
                               file_extensions: Optional[List[str]] = None,
                               recursive: bool = True) -> Dict[str, List[str]]:
        """
        Encuentra archivos duplicados por hash del contenido.

        Args:
            directory: Directorio a analizar
            file_extensions: Lista de extensiones a incluir (ej: ['.pdf', '.txt'])
            recursive: Si buscar recursivamente en subdirectorios

        Returns:
            Diccionario con hash como clave y lista de archivos como valor
        """
        directory = Path(directory)
        if not directory.exists():
            raise FileNotFoundError(f"Directorio no encontrado: {directory}")

        hash_map = defaultdict(list)
        files_processed = 0

        # Obtener lista de archivos
        if recursive:
            pattern = "**/*"
        else:
            pattern = "*"

        for file_path in directory.glob(pattern):
            if not file_path.is_file():
                continue

            # Filtrar por extensiones si se especificaron
            if file_extensions:
                if file_path.suffix.lower() not in [ext.lower() for ext in file_extensions]:
                    continue

            try:
                file_hash = self.calculate_file_hash(file_path)
                hash_map[file_hash].append(str(file_path))
                files_processed += 1

                if files_processed % 100 == 0:
                    self.logger.info(f"Procesados {files_processed} archivos...")

            except Exception as e:
                self.logger.warning(f"Error procesando {file_path}: {e}")
                continue

        # Filtrar solo los hashes que tienen duplicados
        duplicates = {hash_val: files for hash_val, files in hash_map.items() if len(files) > 1}

        self.logger.info(f"Análisis completado: {files_processed} archivos, {len(duplicates)} grupos de duplicados")
        return duplicates

    def find_duplicates_by_name(self, directory: Union[str, Path],
                               case_sensitive: bool = False,
                               recursive: bool = True) -> Dict[str, List[str]]:
        """
        Encuentra archivos duplicados por nombre.

        Args:
            directory: Directorio a analizar
            case_sensitive: Si la comparación es sensible a mayúsculas
            recursive: Si buscar recursivamente en subdirectorios

        Returns:
            Diccionario con nombre como clave y lista de rutas como valor
        """
        directory = Path(directory)
        if not directory.exists():
            raise FileNotFoundError(f"Directorio no encontrado: {directory}")

        name_map = defaultdict(list)

        # Obtener lista de archivos
        if recursive:
            pattern = "**/*"
        else:
            pattern = "*"

        for file_path in directory.glob(pattern):
            if not file_path.is_file():
                continue

            file_name = file_path.name
            if not case_sensitive:
                file_name = file_name.lower()

            name_map[file_name].append(str(file_path))

        # Filtrar solo los nombres que tienen duplicados
        duplicates = {name: files for name, files in name_map.items() if len(files) > 1}

        self.logger.info(f"Encontrados {len(duplicates)} grupos de archivos con nombres duplicados")
        return duplicates

    def find_duplicates_by_size(self, directory: Union[str, Path],
                               recursive: bool = True) -> Dict[int, List[str]]:
        """
        Encuentra archivos duplicados por tamaño.

        Args:
            directory: Directorio a analizar
            recursive: Si buscar recursivamente en subdirectorios

        Returns:
            Diccionario con tamaño como clave y lista de archivos como valor
        """
        directory = Path(directory)
        if not directory.exists():
            raise FileNotFoundError(f"Directorio no encontrado: {directory}")

        size_map = defaultdict(list)

        # Obtener lista de archivos
        if recursive:
            pattern = "**/*"
        else:
            pattern = "*"

        for file_path in directory.glob(pattern):
            if not file_path.is_file():
                continue

            try:
                file_size = file_path.stat().st_size
                size_map[file_size].append(str(file_path))
            except Exception as e:
                self.logger.warning(f"Error obteniendo tamaño de {file_path}: {e}")
                continue

        # Filtrar solo los tamaños que tienen duplicados
        duplicates = {size: files for size, files in size_map.items() if len(files) > 1}

        self.logger.info(f"Encontrados {len(duplicates)} grupos de archivos con tamaños duplicados")
        return duplicates

    def find_duplicates_hybrid(self, directory: Union[str, Path],
                              file_extensions: Optional[List[str]] = None,
                              recursive: bool = True) -> Dict[str, List[str]]:
        """
        Método híbrido optimizado: primero filtra por tamaño, luego calcula hash.

        Más eficiente para grandes volúmenes de archivos ya que evita calcular
        hash de archivos que no pueden ser duplicados (tamaños únicos).

        Args:
            directory: Directorio a analizar
            file_extensions: Lista de extensiones a incluir
            recursive: Si buscar recursivamente en subdirectorios

        Returns:
            Diccionario con hash como clave y lista de archivos como valor
        """
        self.logger.info("Iniciando detección híbrida (tamaño + hash)")

        # Paso 1: Agrupar por tamaño
        size_groups = self.find_duplicates_by_size(directory, recursive)

        if not size_groups:
            self.logger.info("No se encontraron archivos con tamaños duplicados")
            return {}

        # Paso 2: Para cada grupo de tamaño, calcular hash solo si hay múltiples archivos
        hash_duplicates = {}
        total_candidates = sum(len(files) for files in size_groups.values())

        self.logger.info(f"Calculando hash para {total_candidates} archivos candidatos...")

        for size, files in size_groups.items():
            if len(files) < 2:
                continue

            # Filtrar por extensiones si se especificaron
            if file_extensions:
                files = [f for f in files if Path(f).suffix.lower() in [ext.lower() for ext in file_extensions]]
                if len(files) < 2:
                    continue

            # Calcular hash para archivos del mismo tamaño
            hash_group = defaultdict(list)
            for file_path in files:
                try:
                    file_hash = self.calculate_file_hash(file_path)
                    hash_group[file_hash].append(file_path)
                except Exception as e:
                    self.logger.warning(f"Error calculando hash de {file_path}: {e}")
                    continue

            # Agregar solo los hashes que tienen duplicados reales
            for hash_val, hash_files in hash_group.items():
                if len(hash_files) > 1:
                    hash_duplicates[hash_val] = hash_files

        self.logger.info(f"Detección híbrida completada: {len(hash_duplicates)} grupos de duplicados reales")
        return hash_duplicates

    def compare_directories(self, dir1: Union[str, Path], dir2: Union[str, Path],
                           method: str = 'hash') -> Dict[str, Dict]:
        """
        Compara dos directorios para encontrar archivos duplicados entre ellos.

        Args:
            dir1: Primer directorio
            dir2: Segundo directorio
            method: Método de comparación ('hash', 'name', 'size')

        Returns:
            Diccionario con información sobre duplicados entre directorios
        """
        dir1_path = Path(dir1)
        dir2_path = Path(dir2)

        if not dir1_path.exists():
            raise FileNotFoundError(f"Directorio no encontrado: {dir1_path}")
        if not dir2_path.exists():
            raise FileNotFoundError(f"Directorio no encontrado: {dir2_path}")

        self.logger.info(f"Comparando directorios usando método: {method}")

        # Obtener archivos de cada directorio según el método
        if method == 'hash':
            files1 = self._get_files_with_hash(dir1_path)
            files2 = self._get_files_with_hash(dir2_path)
            comparison_key = 'hash'
        elif method == 'name':
            files1 = self._get_files_with_name(dir1_path)
            files2 = self._get_files_with_name(dir2_path)
            comparison_key = 'name'
        elif method == 'size':
            files1 = self._get_files_with_size(dir1_path)
            files2 = self._get_files_with_size(dir2_path)
            comparison_key = 'size'
        else:
            raise ValueError("method debe ser 'hash', 'name' o 'size'")

        # Encontrar intersecciones
        keys1 = set(files1.keys())
        keys2 = set(files2.keys())
        common_keys = keys1.intersection(keys2)

        duplicates = {}
        for key in common_keys:
            duplicates[key] = {
                'dir1_files': files1[key],
                'dir2_files': files2[key],
                'comparison_method': method
            }

        result = {
            'duplicates': duplicates,
            'stats': {
                'total_dir1': len(files1),
                'total_dir2': len(files2),
                'common_items': len(common_keys),
                'unique_dir1': len(keys1 - keys2),
                'unique_dir2': len(keys2 - keys1)
            }
        }

        self.logger.info(f"Comparación completada: {len(common_keys)} elementos comunes encontrados")
        return result

    def _get_files_with_hash(self, directory: Path) -> Dict[str, List[str]]:
        """Obtiene archivos agrupados por hash."""
        hash_map = defaultdict(list)
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                try:
                    file_hash = self.calculate_file_hash(file_path)
                    hash_map[file_hash].append(str(file_path))
                except Exception:
                    continue
        return dict(hash_map)

    def _get_files_with_name(self, directory: Path) -> Dict[str, List[str]]:
        """Obtiene archivos agrupados por nombre."""
        name_map = defaultdict(list)
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                name_map[file_path.name].append(str(file_path))
        return dict(name_map)

    def _get_files_with_size(self, directory: Path) -> Dict[int, List[str]]:
        """Obtiene archivos agrupados por tamaño."""
        size_map = defaultdict(list)
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                try:
                    size = file_path.stat().st_size
                    size_map[size].append(str(file_path))
                except Exception:
                    continue
        return dict(size_map)

    def export_results(self, duplicates: Dict, output_file: Union[str, Path],
                      format: str = 'json') -> None:
        """
        Exporta los resultados de duplicados a un archivo.

        Args:
            duplicates: Diccionario de duplicados obtenido de find_duplicates_*
            output_file: Archivo de salida
            format: Formato de exportación ('json', 'csv')
        """
        output_file = Path(output_file)
        timestamp = datetime.now().isoformat()

        if format.lower() == 'json':
            export_data = {
                'timestamp': timestamp,
                'hash_method': self.hash_method,
                'total_duplicate_groups': len(duplicates),
                'total_duplicate_files': sum(len(files) for files in duplicates.values()),
                'duplicates': duplicates
            }

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

        elif format.lower() == 'csv':
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Grupo', 'Hash/Identificador', 'Archivo', 'Tamaño_Bytes', 'Timestamp'])

                for group_idx, (identifier, files) in enumerate(duplicates.items(), 1):
                    for file_path in files:
                        try:
                            size = Path(file_path).stat().st_size
                        except:
                            size = 'N/A'
                        writer.writerow([group_idx, identifier, file_path, size, timestamp])
        else:
            raise ValueError("format debe ser 'json' o 'csv'")

        self.logger.info(f"Resultados exportados a: {output_file}")

    def get_duplicate_stats(self, duplicates: Dict) -> Dict[str, int]:
        """
        Obtiene estadísticas de los duplicados encontrados.

        Args:
            duplicates: Diccionario de duplicados

        Returns:
            Diccionario con estadísticas
        """
        total_files = sum(len(files) for files in duplicates.values())
        total_groups = len(duplicates)

        # Calcular espacio desperdiciado (archivos duplicados menos uno por grupo)
        wasted_files = total_files - total_groups if total_groups > 0 else 0

        # Calcular tamaños si es posible
        total_size = 0
        wasted_size = 0

        for files in duplicates.values():
            if files:
                try:
                    # Usar el primer archivo para obtener el tamaño
                    file_size = Path(files[0]).stat().st_size
                    total_size += file_size * len(files)
                    wasted_size += file_size * (len(files) - 1)
                except:
                    continue

        return {
            'total_duplicate_groups': total_groups,
            'total_duplicate_files': total_files,
            'wasted_files': wasted_files,
            'total_size_bytes': total_size,
            'wasted_size_bytes': wasted_size,
            'wasted_size_mb': round(wasted_size / (1024 * 1024), 2),
            'wasted_size_gb': round(wasted_size / (1024 * 1024 * 1024), 2)
        }


def quick_duplicate_scan(directory: Union[str, Path], method: str = 'hybrid',
                        file_extensions: Optional[List[str]] = None) -> Dict:
    """
    Función de conveniencia para escaneo rápido de duplicados.

    Args:
        directory: Directorio a escanear
        method: Método de detección ('hash', 'name', 'size', 'hybrid')
        file_extensions: Lista de extensiones a incluir

    Returns:
        Diccionario con duplicados y estadísticas
    """
    detector = DuplicateDetector()

    if method == 'hash':
        duplicates = detector.find_duplicates_by_hash(directory, file_extensions)
    elif method == 'name':
        duplicates = detector.find_duplicates_by_name(directory)
    elif method == 'size':
        duplicates = detector.find_duplicates_by_size(directory)
    elif method == 'hybrid':
        duplicates = detector.find_duplicates_hybrid(directory, file_extensions)
    else:
        raise ValueError("method debe ser 'hash', 'name', 'size' o 'hybrid'")

    stats = detector.get_duplicate_stats(duplicates)

    return {
        'duplicates': duplicates,
        'stats': stats,
        'method_used': method
    }


# Función para compatibilidad con el código existente del proyecto
def merge_classifications_detect_duplicates(dir1_files: List[str], dir2_files: List[str],
                                          method: str = 'name') -> Set[str]:
    """
    Detecta duplicados entre dos listas de archivos (por compatibilidad).

    Args:
        dir1_files: Lista de archivos del primer directorio
        dir2_files: Lista de archivos del segundo directorio
        method: Método de comparación ('name' o 'hash')

    Returns:
        Set de archivos duplicados
    """
    duplicados = set()

    if method == 'name':
        names1 = {Path(f).name for f in dir1_files}
        names2 = {Path(f).name for f in dir2_files}
        common_names = names1.intersection(names2)

        for name in common_names:
            # Encontrar archivos con ese nombre en ambas listas
            files1 = [f for f in dir1_files if Path(f).name == name]
            files2 = [f for f in dir2_files if Path(f).name == name]
            duplicados.update(files2)  # Marcar los del segundo directorio como duplicados

    elif method == 'hash':
        detector = DuplicateDetector()

        # Crear mapeo de hash a archivos para el primer directorio
        hash1_map = {}
        for file_path in dir1_files:
            try:
                file_hash = detector.calculate_file_hash(file_path)
                hash1_map[file_hash] = file_path
            except Exception:
                continue

        # Verificar archivos del segundo directorio
        for file_path in dir2_files:
            try:
                file_hash = detector.calculate_file_hash(file_path)
                if file_hash in hash1_map:
                    duplicados.add(file_path)
            except Exception:
                continue

    return duplicados


if __name__ == "__main__":
    # Ejemplo de uso cuando se ejecuta directamente
    import sys

    if len(sys.argv) < 2:
        print("Uso: python duplicate_detector.py <directorio> [método]")
        print("Métodos disponibles: hash, name, size, hybrid")
        sys.exit(1)

    directory = sys.argv[1]
    method = sys.argv[2] if len(sys.argv) > 2 else 'hybrid'

    print(f"Escaneando {directory} usando método: {method}")
    result = quick_duplicate_scan(directory, method)

    print(f"\nResultados:")
    print(f"Grupos de duplicados: {result['stats']['total_duplicate_groups']}")
    print(f"Archivos duplicados: {result['stats']['total_duplicate_files']}")
    print(f"Espacio desperdiciado: {result['stats']['wasted_size_mb']} MB")

    # Exportar resultados
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"duplicados_{method}_{timestamp}.json"

    detector = DuplicateDetector()
    detector.export_results(result['duplicates'], output_file)
    print(f"\nResultados guardados en: {output_file}")