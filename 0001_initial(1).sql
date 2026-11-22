CREATE TABLE IF NOT EXISTS products (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '', price REAL, image_url TEXT NOT NULL DEFAULT '',
 is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
 id TEXT PRIMARY KEY, customer_name TEXT NOT NULL, phone TEXT NOT NULL,
 address TEXT NOT NULL DEFAULT '', items TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new',
 language TEXT NOT NULL DEFAULT 'ar', created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_products_active_created ON products(is_active,created_at DESC);
