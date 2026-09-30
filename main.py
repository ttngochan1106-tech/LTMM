import sys
import hashlib
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QMessageBox, QStackedWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame, QDoubleSpinBox
)

from database import get_connection, init_db, show_database
from crypto_utils import generate_key_pair, hash_transaction, sign_data, verify_signature


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def money(value):
    return f"{value:,.0f} VNĐ"


class WalletApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_user = None
        self.setWindowTitle("Digital Wallet - RSA Signature")
        self.resize(1100, 720)
        self.setMinimumSize(900, 620)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_page = self.build_login()
        self.register_page = self.build_register()
        self.dashboard_page = self.build_dashboard()
        self.transfer_page = self.build_transfer()
        self.transactions_page = self.build_transactions()

        for page in [
            self.login_page, self.register_page, self.dashboard_page,
            self.transfer_page, self.transactions_page
        ]:
            self.stack.addWidget(page)

        self.show_login()

    # ---------- common ----------
    def title(self, text):
        label = QLabel(text)
        label.setObjectName("Title")
        return label

    def subtitle(self, text):
        label = QLabel(text)
        label.setObjectName("Subtitle")
        label.setWordWrap(True)
        return label

    def button(self, text, slot, primary=False):
        b = QPushButton(text)
        b.clicked.connect(slot)
        b.setProperty("primary", primary)
        b.setCursor(Qt.PointingHandCursor)
        return b

    def show_login(self):
        self.login_user.clear()
        self.login_pass.clear()
        self.stack.setCurrentWidget(self.login_page)

    def logout(self):
        self.current_user = None
        self.show_login()

    def get_user(self, user_id):
        conn = get_connection()
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        conn.close()
        return row

    def refresh_current_user(self):
        if self.current_user:
            self.current_user = self.get_user(self.current_user["id"])

    # ---------- login ----------
    def build_login(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(100, 70, 100, 70)

        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(55, 45, 55, 45)
        layout.setSpacing(16)

        brand = QLabel("🔐 DIGITAL WALLET")
        brand.setObjectName("Brand")
        layout.addWidget(brand)

        layout.addWidget(self.title("Welcome back"))
        layout.addWidget(self.subtitle("Đăng nhập để quản lý số dư và xác minh giao dịch bằng chữ ký RSA."))

        self.login_user = QLineEdit()
        self.login_user.setPlaceholderText("Số tài khoản")
        self.login_pass = QLineEdit()
        self.login_pass.setPlaceholderText("Mật khẩu")
        self.login_pass.setEchoMode(QLineEdit.Password)

        layout.addWidget(self.login_user)
        layout.addWidget(self.login_pass)
        layout.addSpacing(8)
        layout.addWidget(self.button("Đăng nhập", self.login, True))
        layout.addWidget(self.button("Tạo tài khoản mới", lambda: self.stack.setCurrentWidget(self.register_page)))

        outer.addStretch()
        outer.addWidget(card)
        outer.addStretch()
        return page

    def login(self):
        account_number = self.login_user.text().strip()
        password = self.login_pass.text()

        if not account_number or not password:
            QMessageBox.warning(self, "Thiếu thông tin", "Vui lòng nhập số tài khoản và mật khẩu.")
            return

        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM users WHERE account_number=? AND password=?",
            (account_number, hash_password(password))
        ).fetchone()
        conn.close()

        if not row:
            QMessageBox.warning(self, "Đăng nhập thất bại", "Sai số tài khoản hoặc mật khẩu.")
            return

        self.current_user = row
        self.refresh_dashboard()
        self.stack.setCurrentWidget(self.dashboard_page)

    # ---------- register ----------
    def build_register(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(100, 70, 100, 70)

        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(55, 45, 55, 45)
        layout.setSpacing(14)

        layout.addWidget(self.title("Create account"))
        layout.addWidget(self.subtitle("Tài khoản mới sẽ được tạo một cặp khóa RSA dùng cho chữ ký số."))

        self.reg_user = QLineEdit()
        self.reg_user.setPlaceholderText("Tên hiển thị")
        self.reg_pass = QLineEdit()
        self.reg_pass.setPlaceholderText("Mật khẩu")
        self.reg_pass.setEchoMode(QLineEdit.Password)
        self.reg_pass2 = QLineEdit()
        self.reg_pass2.setPlaceholderText("Nhập lại mật khẩu")
        self.reg_pass2.setEchoMode(QLineEdit.Password)

        for w in [self.reg_user, self.reg_pass, self.reg_pass2]:
            layout.addWidget(w)

        layout.addWidget(self.button("Đăng ký", self.register, True))
        layout.addWidget(self.button("Quay lại đăng nhập", self.show_login))

        outer.addStretch()
        outer.addWidget(card)
        outer.addStretch()
        return page

    def register(self):
        username = self.reg_user.text().strip()
        password = self.reg_pass.text()
        password2 = self.reg_pass2.text()

        if not username or not password:
            QMessageBox.warning(self, "Thiếu thông tin", "Vui lòng nhập đầy đủ thông tin.")
            return
        if password != password2:
            QMessageBox.warning(self, "Lỗi", "Hai mật khẩu không giống nhau.")
            return

        private_key, public_key = generate_key_pair()

        try:
            conn = get_connection()

            # Tạo số tài khoản mới
            row = conn.execute(
                """
                SELECT MAX(CAST(account_number AS INTEGER)) AS max_account
                FROM users
                WHERE account_number IS NOT NULL
                """
            ).fetchone()

            if row["max_account"] is None:
                account_number = "10000001"
            else:
                account_number = str(row["max_account"] + 1)

            conn.execute(
                """
                INSERT INTO users(
                    account_number,
                    username,
                    password,
                    private_key,
                    public_key,
                    balance
                )
                VALUES(?,?,?,?,?,?)
                """,
                (
                    account_number,
                    username,
                    hash_password(password),
                    private_key,
                    public_key,
                    0
                )
            )

            conn.commit()

        except Exception as e:
            QMessageBox.warning(
                self,
                "Lỗi",
                f"Không thể tạo tài khoản.\n{e}"
            )
            return
        finally:
            try:
                conn.close()
            except:
                pass

            QMessageBox.information(
                self,
                "Thành công",
                f"Đã tạo tài khoản thành công!\n\n"
                f"Số tài khoản của bạn: {account_number}\n\n"
                f"Hãy lưu số tài khoản để đăng nhập."
            )
            self.show_login()

      

    # ---------- dashboard ----------
    def build_dashboard(self):
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(35, 30, 35, 30)
        root.setSpacing(20)

        top = QHBoxLayout()
        self.welcome = QLabel()
        self.welcome.setObjectName("Welcome")
        top.addWidget(self.welcome)
        top.addStretch()
        top.addWidget(self.button("Đăng xuất", self.logout))
        root.addLayout(top)

        balance_card = QFrame()
        balance_card.setObjectName("BalanceCard")
        bl = QVBoxLayout(balance_card)
        bl.setContentsMargins(30, 25, 30, 25)
        small = QLabel("AVAILABLE BALANCE")
        small.setObjectName("SmallLabel")
        self.balance_label = QLabel("0 VNĐ")
        self.balance_label.setObjectName("Balance")
        bl.addWidget(small)
        bl.addWidget(self.balance_label)
        root.addWidget(balance_card)

        actions = QHBoxLayout()
        actions.addWidget(self.button("💰  Nạp tiền", self.deposit_dialog, True))
        actions.addWidget(self.button("💸  Chuyển tiền", lambda: self.stack.setCurrentWidget(self.transfer_page)))
        actions.addWidget(self.button("📜  Lịch sử giao dịch", self.show_transactions))
        root.addLayout(actions)

        crypto = QFrame()
        crypto.setObjectName("CryptoCard")
        cl = QVBoxLayout(crypto)
        cl.setContentsMargins(25, 20, 25, 20)
        cl.addWidget(QLabel("🔐 CRYPTOGRAPHY PROTECTION"))
        info = QLabel(
            "Mỗi giao dịch thay đổi số dư được băm bằng SHA-256 và ký bằng RSA private key. "
            "Khi xác minh, RSA public key được dùng để phát hiện dữ liệu bị sửa."
        )
        info.setWordWrap(True)
        cl.addWidget(info)
        root.addWidget(crypto)
        root.addStretch()
        return page

    def refresh_dashboard(self):
        self.refresh_current_user()
        self.welcome.setText(
            f"Xin chào, {self.current_user['username']} 👋\n"
            f"Số tài khoản: {self.current_user['account_number']}"
        )
        self.balance_label.setText(money(self.current_user["balance"]))

    def deposit_dialog(self):
        amount = QDoubleSpinBox()
        amount.setRange(1, 1000000000)
        amount.setDecimals(0)
        amount.setValue(500000)
        amount.setSuffix(" VNĐ")

        box = QMessageBox(self)
        box.setWindowTitle("Nạp tiền")
        box.setText("Nhập số tiền muốn nạp:")
        box.layout().addWidget(amount, 1, 1)

        ok = box.addButton("Nạp", QMessageBox.AcceptRole)
        box.addButton("Hủy", QMessageBox.RejectRole)
        box.exec()

        if box.clickedButton() != ok:
            return

        value = amount.value()
        conn = get_connection()
        user = conn.execute("SELECT * FROM users WHERE id=?", (self.current_user["id"],)).fetchone()
        new_balance = user["balance"] + value
        conn.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, user["id"]))
        conn.commit()
        conn.close()

        self.refresh_dashboard()
        QMessageBox.information(self, "Thành công", f"Đã nạp {money(value)}.")

    # ---------- transfer ----------
    def build_transfer(self):
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(60, 45, 60, 45)

        root.addWidget(self.title("Chuyển tiền"))
        root.addWidget(self.subtitle("Phiên giao dịch sẽ được tạo hash SHA-256 và chữ ký RSA trước khi lưu."))

        self.receiver = QLineEdit()
        self.receiver.setPlaceholderText("Số tài khoản người nhận")
        self.transfer_amount = QDoubleSpinBox()
        self.transfer_amount.setRange(1, 1000000000)
        self.transfer_amount.setDecimals(0)
        self.transfer_amount.setSuffix(" VNĐ")

        root.addWidget(QLabel("Số tài khoản người nhận"))
        root.addWidget(self.receiver)
        root.addWidget(QLabel("Số tiền"))
        root.addWidget(self.transfer_amount)
        root.addSpacing(10)

        row = QHBoxLayout()
        row.addWidget(self.button("← Quay lại", lambda: self.stack.setCurrentWidget(self.dashboard_page)))
        row.addWidget(self.button("Ký & Chuyển tiền", self.transfer, True))
        root.addLayout(row)
        root.addStretch()
        return page

    def transfer(self):
        receiver_account = self.receiver.text().strip()
        amount = self.transfer_amount.value()

        if not receiver_account:
            QMessageBox.warning(self, "Thiếu thông tin", "Nhập số tài khoản người nhận.")
            return
        if receiver_account == self.current_user["account_number"]:
            QMessageBox.warning(self, "Lỗi", "Không thể chuyển tiền cho chính mình.")
            return

        conn = get_connection()
        sender = conn.execute("SELECT * FROM users WHERE id=?", (self.current_user["id"],)).fetchone()
        receiver = conn.execute("SELECT * FROM users WHERE account_number=?", (receiver_account,)).fetchone()

        if not receiver:
            conn.close()
            QMessageBox.warning(self, "Không tìm thấy", "Số tài khoản không tồn tại.")
            return
        if sender["balance"] < amount:
            conn.close()
            QMessageBox.warning(self, "Không đủ số dư", "Số dư hiện tại không đủ.")
            return

        sender_old = sender["balance"]
        receiver_old = receiver["balance"]
        sender_new = sender_old - amount
        receiver_new = receiver_old + amount
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        transaction_data = (
            f"{sender['id']}|{receiver['id']}|{amount}|"
            f"{sender_old}|{sender_new}|{receiver_old}|{receiver_new}|{timestamp}"
        )
        tx_hash = hash_transaction(transaction_data)
        signature = sign_data(transaction_data, sender["private_key"])

        conn.execute("UPDATE users SET balance=? WHERE id=?", (sender_new, sender["id"]))
        conn.execute("UPDATE users SET balance=? WHERE id=?", (receiver_new, receiver["id"]))
        conn.execute(
            """INSERT INTO transactions(
                sender_id,receiver_id,amount,sender_old_balance,sender_new_balance,
                receiver_old_balance,receiver_new_balance,timestamp,transaction_hash,signature
            ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (sender["id"], receiver["id"], amount, sender_old, sender_new,
             receiver_old, receiver_new, timestamp, tx_hash, signature)
        )
        conn.commit()
        conn.close()

        self.receiver.clear()
        self.transfer_amount.setValue(0)
        self.refresh_dashboard()

        QMessageBox.information(
            self, 
            "Giao dịch thành công",
            f"Đã chuyển {money(amount)} cho"
            f"{receiver['username']}.\n\n"
            f"Số tài khoản: {receiver_account}\n\n"
            f"SHA-256: {tx_hash[:32]}...\n"
            "RSA Signature: CREATED"
        )
        self.stack.setCurrentWidget(self.dashboard_page)

    # ---------- transactions ----------
    def build_transactions(self):
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(35, 30, 35, 30)

        top = QHBoxLayout()
        top.addWidget(self.title("Lịch sử giao dịch"))
        top.addStretch()
        top.addWidget(self.button("← Dashboard", lambda: self.stack.setCurrentWidget(self.dashboard_page)))
        root.addLayout(top)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["ID", "Loại", "Đối tác", "Số tiền", "Thời gian", "SHA-256", "Trạng thái"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        root.addWidget(self.table)

        actions = QHBoxLayout()
        actions.addWidget(self.button("🔍 Xác minh giao dịch", self.verify_selected, True))
        actions.addWidget(self.button("🧪 Demo sửa dữ liệu", self.tamper_selected))
        root.addLayout(actions)

        note = QLabel(
            "Demo: sửa amount trong database nhưng giữ nguyên chữ ký → hash thay đổi → xác minh INVALID."
        )
        note.setObjectName("Hint")
        note.setWordWrap(True)
        root.addWidget(note)
        return page

    def show_transactions(self):
        self.refresh_transactions()
        self.stack.setCurrentWidget(self.transactions_page)

    def refresh_transactions(self):
        conn = get_connection()
        rows = conn.execute(
            """SELECT t.*, s.username AS sender_name, r.username AS receiver_name
               FROM transactions t
               JOIN users s ON s.id=t.sender_id
               JOIN users r ON r.id=t.receiver_id
               WHERE t.sender_id=? OR t.receiver_id=?
               ORDER BY t.id DESC""",
            (self.current_user["id"], self.current_user["id"])
        ).fetchall()
        conn.close()

        self.table.setRowCount(0)
        for row in rows:
            i = self.table.rowCount()
            self.table.insertRow(i)
            outgoing = row["sender_id"] == self.current_user["id"]
            values = [
                str(row["id"]),
                "CHUYỂN" if outgoing else "NHẬN",
                row["receiver_name"] if outgoing else row["sender_name"],
                ("-" if outgoing else "+") + money(row["amount"]),
                row["timestamp"],
                row["transaction_hash"][:18] + "...",
                "Chưa xác minh"
            ]
            for j, value in enumerate(values):
                self.table.setItem(i, j, QTableWidgetItem(value))
            self.table.item(i, 0).setData(Qt.UserRole, row["id"])

    def selected_transaction_id(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        return self.table.item(row, 0).data(Qt.UserRole)

    def verify_selected(self):
        tx_id = self.selected_transaction_id()
        if tx_id is None:
            QMessageBox.warning(self, "Chọn giao dịch", "Hãy chọn một giao dịch.")
            return

        result, details = self.verify_transaction(tx_id)
        if result:
            QMessageBox.information(self, "✓ VALID", details)
        else:
            QMessageBox.critical(self, "✗ INVALID", details)

    def verify_transaction(self, tx_id):
        conn = get_connection()
        tx = conn.execute("SELECT * FROM transactions WHERE id=?", (tx_id,)).fetchone()
        sender = conn.execute("SELECT * FROM users WHERE id=?", (tx["sender_id"],)).fetchone()
        conn.close()

        data = (
            f"{tx['sender_id']}|{tx['receiver_id']}|{tx['amount']}|"
            f"{tx['sender_old_balance']}|{tx['sender_new_balance']}|"
            f"{tx['receiver_old_balance']}|{tx['receiver_new_balance']}|{tx['timestamp']}"
        )
        new_hash = hash_transaction(data)
        hash_ok = new_hash == tx["transaction_hash"]
        signature_ok = verify_signature(data, tx["signature"], sender["public_key"])

        if hash_ok and signature_ok:
            return True, (
                "Chữ ký số hợp lệ.\n\n"
                "✓ SHA-256 hash khớp\n"
                "✓ RSA signature hợp lệ\n"
                "✓ Dữ liệu giao dịch chưa bị thay đổi"
            )

        return False, (
            "Phát hiện dữ liệu không còn khớp với phiên giao dịch đã ký.\n\n"
            f"{'✓' if hash_ok else '✗'} SHA-256 hash\n"
            f"{'✓' if signature_ok else '✗'} RSA signature\n\n"
            "Kết luận: giao dịch có dấu hiệu bị thay đổi."
        )

    def tamper_selected(self):
        tx_id = self.selected_transaction_id()
        if tx_id is None:
            QMessageBox.warning(self, "Chọn giao dịch", "Hãy chọn một giao dịch để demo.")
            return

        conn = get_connection()
        tx = conn.execute("SELECT amount FROM transactions WHERE id=?", (tx_id,)).fetchone()
        new_amount = tx["amount"] + 1000000
        conn.execute("UPDATE transactions SET amount=? WHERE id=?", (new_amount, tx_id))
        conn.commit()
        conn.close()

        QMessageBox.warning(
            self, "Dữ liệu đã bị sửa",
            f"Demo đã đổi số tiền của giao dịch #{tx_id}.\n"
            f"Số tiền mới: {money(new_amount)}\n\n"
            "Chữ ký cũ không được tạo lại. Hãy bấm 'Xác minh giao dịch' để thấy INVALID."
        )
        self.refresh_transactions()


def apply_style(app):
    app.setStyleSheet("""
        QWidget {
            background: #f5f7fb;
            color: #172033;
            font-family: "Segoe UI";
            font-size: 14px;
        }
        QFrame#Card {
            background: white;
            border: 1px solid #e5e9f2;
            border-radius: 18px;
        }
        QFrame#BalanceCard {
            background: #152a56;
            border-radius: 18px;
        }
        QFrame#BalanceCard QLabel {
            color: white;
        }
        QFrame#CryptoCard {
            background: #eef4ff;
            border: 1px solid #d6e3ff;
            border-radius: 16px;
        }
        QLabel#Brand {
            color: #2457d6;
            font-size: 20px;
            font-weight: 800;
        }
        QLabel#Title {
            font-size: 30px;
            font-weight: 800;
        }
        QLabel#Subtitle {
            color: #667085;
            font-size: 14px;
        }
        QLabel#Welcome {
            font-size: 24px;
            font-weight: 750;
        }
        QLabel#SmallLabel {
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 1px;
        }
        QLabel#Balance {
            font-size: 36px;
            font-weight: 800;
        }
        QLabel#Hint {
            color: #667085;
            font-size: 12px;
        }
        QLineEdit, QDoubleSpinBox {
            background: white;
            border: 1px solid #d7dce5;
            border-radius: 10px;
            padding: 12px;
            min-height: 22px;
        }
        QLineEdit:focus, QDoubleSpinBox:focus {
            border: 2px solid #2457d6;
        }
        QPushButton {
            background: white;
            border: 1px solid #d7dce5;
            border-radius: 10px;
            padding: 12px 18px;
            font-weight: 650;
            min-height: 20px;
        }
        QPushButton:hover {
            background: #f0f4ff;
        }
        QPushButton[primary="true"] {
            background: #2457d6;
            color: white;
            border: none;
        }
        QPushButton[primary="true"]:hover {
            background: #1c46b4;
        }
        QTableWidget {
            background: white;
            border: 1px solid #e2e6ee;
            border-radius: 12px;
            gridline-color: #eef0f4;
            padding: 5px;
        }
        QHeaderView::section {
            background: #f0f3f8;
            padding: 10px;
            border: none;
            font-weight: 700;
        }
    """)


if __name__ == "__main__":
    init_db()

    show_database()
    # TEST: thay đổi số tiền giao dịch để kiểm tra chữ ký
    #conn = get_connection()
    #cur = conn.cursor()

    #cur.execute("""
    #    UPDATE transactions
    #    SET amount = 9000000
    #    WHERE id = 1
    #""")

    #conn.commit()
    #conn.close()
    app = QApplication(sys.argv)
    apply_style(app)
    window = WalletApp()
    window.show()
    sys.exit(app.exec())
