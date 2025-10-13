# Database Provider - Secure SQLite operations with SQL injection prevention
# Main functions: exchange() for auth, call() for SQL operations
# Supports: executeQuery, listTables, getSchema operations with security filters

from __future__ import annotations

import os
import re
import sqlite3
import asyncio
from pathlib import Path
from typing import Any, Dict, List

from structlog import get_logger

from .base import ProviderAdapter, register_adapter

logger = get_logger(__name__)


class DatabaseProviderAdapter(ProviderAdapter):
    def __init__(self) -> None:
        super().__init__("database")
        self.db_path = os.getenv("DATABASE_PATH", "./data/app.db")
        self.max_rows = int(os.getenv("DATABASE_MAX_ROWS", "1000"))
        
        # Ensure data directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database with sample table
        self._init_database()
        
        # Dangerous SQL patterns to block
        self.blocked_patterns = [
            r'\bDROP\s+TABLE\b',
            r'\bDROP\s+DATABASE\b',
            r'\bTRUNCATE\b',
            r'\bALTER\s+TABLE\b.*\bDROP\b',
            r'\bDELETE\s+FROM\s+\w+\s*;?\s*$',  # DELETE without WHERE
            r';\s*DROP\b',  # SQL injection attempts
            r'--',  # SQL comments (potential injection)
            r'/\*.*\*/',  # SQL block comments
        ]

    def _init_database(self) -> None:
        """Initialize database with sample tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    product TEXT NOT NULL,
                    amount DECIMAL(10,2),
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)
            
            # Insert sample data if tables are empty
            cursor = conn.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                conn.execute("INSERT INTO users (name, email) VALUES (?, ?)", ("John Doe", "john@example.com"))
                conn.execute("INSERT INTO users (name, email) VALUES (?, ?)", ("Jane Smith", "jane@example.com"))
                conn.execute("INSERT INTO orders (user_id, product, amount) VALUES (?, ?, ?)", (1, "Laptop", 999.99))
                conn.execute("INSERT INTO orders (user_id, product, amount) VALUES (?, ?, ?)", (2, "Phone", 599.99))
            
            conn.commit()

    async def exchange(self, scopes: list[str], subject: str, tenant: str, purpose: str) -> dict:
        """Return mock token metadata - SQLite doesn't need external auth"""
        logger.info(
            "database_provider.exchange",
            tenant=tenant,
            subject=subject,
            purpose=purpose,
        )
        return {
            "access_token": "sqlite_local",
            "token_type": "Bearer",
            "expires_in": 3600,
            "audience": "database",
        }

    async def call(self, endpoint: str, payload: dict) -> dict:
        """Route to appropriate database operation"""
        if endpoint == "executeQuery":
            return await self.execute_query(payload)
        elif endpoint == "listTables":
            return await self.list_tables(payload)
        elif endpoint == "getSchema":
            return await self.get_schema(payload)
        raise ValueError(f"unsupported endpoint: {endpoint}")

    def _validate_sql(self, query: str) -> None:
        """Validate SQL query for security"""
        query_upper = query.upper().strip()
        
        # Check for blocked patterns
        for pattern in self.blocked_patterns:
            if re.search(pattern, query_upper, re.IGNORECASE):
                raise ValueError(f"Blocked SQL operation detected: {pattern}")
        
        # Ensure DELETE has WHERE clause
        if query_upper.startswith('DELETE FROM'):
            if 'WHERE' not in query_upper:
                raise ValueError("DELETE queries must include WHERE clause")
        
        # Basic SQL injection prevention
        if ';' in query and not query.strip().endswith(';'):
            raise ValueError("Multiple statements not allowed")

    async def execute_query(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute SQL query with security validation (offloaded to thread)."""
        query = payload["query"].strip()
        params = payload.get("params", [])

        # Validate query on event loop (cheap)
        self._validate_sql(query)

        def _do_execute_query() -> Dict[str, Any]:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute(query, params)

                    if query.upper().strip().startswith(("SELECT", "WITH")):
                        rows = cursor.fetchmany(self.max_rows)
                        columns = [d[0] for d in cursor.description] if cursor.description else []
                        data = [dict(row) for row in rows]
                        result = {
                            "rows": data,
                            "columns": columns,
                            "count": len(data),
                            "query": query,
                            "type": "SELECT",
                        }
                    else:
                        conn.commit()
                        result = {
                            "affected_rows": cursor.rowcount,
                            "query": query,
                            "type": "MODIFY",
                            "last_row_id": cursor.lastrowid if cursor.lastrowid else None,
                        }

                    logger.info(
                        "database_provider.execute_query",
                        query_type=result["type"],
                        affected_rows=result.get("affected_rows", result.get("count")),
                    )
                    return result
            except sqlite3.Error as e:
                logger.error("database_provider.execute_query_error", error=str(e), query=query)
                raise ValueError(f"Database error: {str(e)}")

        return await asyncio.to_thread(_do_execute_query)

    async def list_tables(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """List all tables in the database (offloaded to thread)."""
        def _do_list_tables() -> Dict[str, Any]:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute(
                        """
                        SELECT name, type FROM sqlite_master 
                        WHERE type='table' AND name NOT LIKE 'sqlite_%'
                        ORDER BY name
                        """
                    )

                    tables = []
                    for row in cursor.fetchall():
                        table_name = row[0]
                        count_cursor = conn.execute(f"SELECT COUNT(*) FROM {table_name}")
                        row_count = count_cursor.fetchone()[0]
                        tables.append({
                            "name": table_name,
                            "type": row[1],
                            "row_count": row_count,
                        })

                    logger.info("database_provider.list_tables", table_count=len(tables))
                    return {"tables": tables, "count": len(tables)}
            except sqlite3.Error as e:
                logger.error("database_provider.list_tables_error", error=str(e))
                raise ValueError(f"Database error: {str(e)}")

        return await asyncio.to_thread(_do_list_tables)

    async def get_schema(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Get schema information for a specific table (offloaded to thread)."""
        table_name = payload["table_name"]

        # Validate table name (prevent injection) on event loop
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", table_name):
            raise ValueError("Invalid table name")

        def _do_get_schema() -> Dict[str, Any]:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute(f"PRAGMA table_info({table_name})")
                    columns: List[Dict[str, Any]] = []
                    for row in cursor.fetchall():
                        columns.append(
                            {
                                "name": row[1],
                                "type": row[2],
                                "not_null": bool(row[3]),
                                "default_value": row[4],
                                "primary_key": bool(row[5]),
                            }
                        )

                    if not columns:
                        raise ValueError(f"Table '{table_name}' not found")

                    fk_cursor = conn.execute(f"PRAGMA foreign_key_list({table_name})")
                    foreign_keys: List[Dict[str, Any]] = []
                    for fk_row in fk_cursor.fetchall():
                        foreign_keys.append(
                            {
                                "column": fk_row[3],
                                "references_table": fk_row[2],
                                "references_column": fk_row[4],
                            }
                        )

                    logger.info("database_provider.get_schema", table=table_name, columns=len(columns))
                    return {
                        "table_name": table_name,
                        "columns": columns,
                        "foreign_keys": foreign_keys,
                        "column_count": len(columns),
                    }
            except sqlite3.Error as e:
                logger.error("database_provider.get_schema_error", error=str(e), table=table_name)
                raise ValueError(f"Database error: {str(e)}")

        return await asyncio.to_thread(_do_get_schema)


# Auto-register on import
register_adapter(DatabaseProviderAdapter())
