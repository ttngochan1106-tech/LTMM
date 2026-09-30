import sqlite3

DATABASE = "wallet.db"


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def generate_account_number(cur):
    row = cur.execute(
        """
        SELECT MAX(CAST(account_number AS INTEGER)) AS max_account
        FROM users
        WHERE account_number IS NOT NULL
        """
    ).fetchone()

    if row["max_account"] is None:
        return "10000001"

    return str(row["max_account"] + 1)


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    # ==========================================
    # Nếu chưa có bảng users -> tạo mới
    # ==========================================
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_number TEXT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            private_key TEXT NOT NULL,
            public_key TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0
        )
    """)

    # Kiểm tra các cột hiện tại
    columns = [
        row["name"]
        for row in cur.execute("PRAGMA table_info(users)").fetchall()
    ]

    # ==========================================
    # Nếu database cũ chưa có account_number
    # ==========================================
    if "account_number" not in columns:
        cur.execute(
            "ALTER TABLE users ADD COLUMN account_number TEXT"
        )

    # ==========================================
    # Kiểm tra username có đang UNIQUE không
    # ==========================================
    unique_username = False

    indexes = cur.execute(
        "PRAGMA index_list(users)"
    ).fetchall()

    for index in indexes:
        index_name = index["name"]

        index_info = cur.execute(
            f'PRAGMA index_info("{index_name}")'
        ).fetchall()

        index_columns = [x["name"] for x in index_info]

        if index["unique"] and "username" in index_columns:
            unique_username = True
            break

    # ==========================================
    # Nếu username đang UNIQUE
    # thì phải rebuild bảng users
    # ==========================================
    if unique_username:

        # Xóa bảng tạm nếu chẳng may còn tồn tại
        cur.execute("DROP TABLE IF EXISTS users_new")

        cur.execute("""
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_number TEXT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                private_key TEXT NOT NULL,
                public_key TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0
            )
        """)

        users = cur.execute(
            """
            SELECT
                id,
                account_number,
                username,
                password,
                private_key,
                public_key,
                balance
            FROM users
            ORDER BY id
            """
        ).fetchall()

        for user in users:

            account_number = user["account_number"]

            # Nếu tài khoản cũ chưa có số tài khoản
            if not account_number:
                account_number = f"{10000000 + user['id']}"

            cur.execute(
                """
                INSERT INTO users_new(
                    id,
                    account_number,
                    username,
                    password,
                    private_key,
                    public_key,
                    balance
                )
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    user["id"],
                    account_number,
                    user["username"],
                    user["password"],
                    user["private_key"],
                    user["public_key"],
                    user["balance"]
                )
            )

        # Xóa bảng cũ
        cur.execute("DROP TABLE users")

        # Đổi bảng mới thành users
        cur.execute(
            "ALTER TABLE users_new RENAME TO users"
        )

    # ==========================================
    # Cấp số tài khoản cho user chưa có
    # ==========================================
    users_without_account = cur.execute(
        """
        SELECT id
        FROM users
        WHERE account_number IS NULL
           OR account_number = ''
        ORDER BY id
        """
    ).fetchall()

    for user in users_without_account:

        account_number = f"{10000000 + user['id']}"

        cur.execute(
            """
            UPDATE users
            SET account_number = ?
            WHERE id = ?
            """,
            (account_number, user["id"])
        )

    # ==========================================
    # Số tài khoản phải UNIQUE
    # ==========================================
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_users_account_number
        ON users(account_number)
    """)

    # ==========================================
    # Bảng transactions
    # ==========================================
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            sender_old_balance REAL NOT NULL,
            sender_new_balance REAL NOT NULL,
            receiver_old_balance REAL NOT NULL,
            receiver_new_balance REAL NOT NULL,
            timestamp TEXT NOT NULL,
            transaction_hash TEXT NOT NULL,
            signature TEXT NOT NULL
        )
    """)

def show_database():
    conn = get_connection()

    print("\n" + "=" * 100)
    print("                         USERS")
    print("=" * 100)

    users = conn.execute("""
        SELECT
            id,
            account_number,
            username,
            password,
            balance
        FROM users
        ORDER BY id
    """).fetchall()

    print(
        f"{'ID':<5}"
        f"{'ACCOUNT':<15}"
        f"{'USERNAME':<15}"
        f"{'PASSWORD HASH':<70}"
        f"{'BALANCE':<15}"
    )

    print("-" * 120)

    for user in users:
        print(
            f"{user['id']:<5}"
            f"{user['account_number']:<15}"
            f"{user['username']:<15}"
            f"{user['password']:<70}"
            f"{user['balance']:<15}"
        )

    print("\n" + "=" * 100)
    print("                       TRANSACTIONS")
    print("=" * 100)

    transactions = conn.execute("""
        SELECT
            id,
            sender_id,
            receiver_id,
            amount,
            timestamp,
            transaction_hash,
            signature
        FROM transactions
        ORDER BY id
    """).fetchall()

    print(
        f"{'ID':<5}"
        f"{'SENDER':<10}"
        f"{'RECEIVER':<10}"
        f"{'AMOUNT':<15}"
        f"{'TIME':<22}"
        f"{'HASH':<25}"
        f"{'SIGNATURE':<30}"
    )

    print("-" * 120)

    for tx in transactions:
        print(
            f"{tx['id']:<5}"
            f"{tx['sender_id']:<10}"
            f"{tx['receiver_id']:<10}"
            f"{tx['amount']:<15.0f}"
            f"{tx['timestamp']:<22}"
            f"{tx['transaction_hash'][:22] + '...':<25}"
            f"{tx['signature'][:27] + '...':<30}"
        )

    print("=" * 100)


    conn.commit()
    conn.close()
