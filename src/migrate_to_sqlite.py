import os
from sqlalchemy import create_engine
from src.database import Base

# Source: The running Postgres container
PG_URL = "postgresql://admin:adminpass@db:5432/rss_db"

# Destination: The new SQLite volume map
SQLITE_URL = "sqlite:////app/data/noc_fusion.db"

print(" Connecting to Postgres source...")
pg_engine = create_engine(PG_URL)

print(" Connecting to SQLite destination...")
os.makedirs("/app/data", exist_ok=True)
sqlite_engine = create_engine(SQLITE_URL)

print(" Building schema...")
Base.metadata.create_all(bind=sqlite_engine)

print(" Transferring data...")
with pg_engine.connect() as pg_conn:
    with sqlite_engine.connect() as sq_conn:
        for table_name, table in Base.metadata.tables.items():
            print(f" Table: {table_name}...")
            
            # WIPE OUT any auto-generated data Streamlit might have just created
            sq_conn.execute(table.delete())
            sq_conn.commit()
            
            data = pg_conn.execute(table.select()).fetchall()
            
            if data:
                dicts = [dict(row._mapping) for row in data]
                sq_conn.execute(table.insert(), dicts)
                sq_conn.commit()
                print(f"  [OK] {len(dicts)} rows transferred.")
            else:
                print(f"   Empty. Skipped.")

print(" Done! Data safely written to /app/data/noc_fusion.db")