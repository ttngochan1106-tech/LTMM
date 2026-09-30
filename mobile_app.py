
import sys
import hashlib
from datetime import datetime

from PySide6.QtCore import Qt, Signal, QPoint, QTimer
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QLineEdit, QStackedWidget, QFrame, QScrollArea,
    QDialog, QButtonGroup
)

from database import get_connection, init_db, generate_account_number
from crypto_utils import generate_key_pair, hash_transaction, sign_data, verify_signature


# =====================================================================
# Helpers
# =====================================================================
def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def money(value):
    return f"{value:,.0f} VNĐ"


def short_hash(h, head=14, tail=8):
    return h if len(h) <= head + tail + 1 else f"{h[:head]}…{h[-tail:]}"


def tx_payload(sender_id, receiver_id, amount, s_old, s_new, r_old, r_new, timestamp):
    """Chuỗi dữ liệu được băm + ký. PHẢI giống hệt main.py để xác minh chéo được."""
    return f"{sender_id}|{receiver_id}|{amount}|{s_old}|{s_new}|{r_old}|{r_new}|{timestamp}"


# =====================================================================
# Bank: toàn bộ nghiệp vụ (không phụ thuộc Qt)
# =====================================================================
class Bank:
    @staticmethod
    def authenticate(account_number, password):
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM users WHERE account_number=? AND password=?",
            (account_number, hash_password(password))
        ).fetchone()
        conn.close()
        return row

    @staticmethod
    def register(username, password):
        """Trả về số tài khoản mới."""
        private_key, public_key = generate_key_pair()
        conn = get_connection()
        try:
            cur = conn.cursor()
            account_number = generate_account_number(cur)
            cur.execute(
                """INSERT INTO users(account_number, username, password,
                                     private_key, public_key, balance)
                   VALUES(?,?,?,?,?,0)""",
                (account_number, username, hash_password(password), private_key, public_key)
            )
            conn.commit()
            return account_number
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def get_user(user_id):
        conn = get_connection()
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        conn.close()
        return row

    @staticmethod
    def find_account(account_number):
        conn = get_connection()
        row = conn.execute(
            "SELECT id, username, account_number FROM users WHERE account_number=?",
            (account_number,)
        ).fetchone()
        conn.close()
        return row

    @staticmethod
    def deposit(user_id, amount):
        conn = get_connection()
        try:
            conn.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount, user_id))
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def transfer(sender_id, receiver_account, amount):
        """Băm SHA-256 + ký RSA + cập nhật số dư trong 1 transaction. -> (tx_id, lỗi)"""
        amount = float(amount)
        conn = get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            sender = conn.execute("SELECT * FROM users WHERE id=?", (sender_id,)).fetchone()
            receiver = conn.execute(
                "SELECT * FROM users WHERE account_number=?", (receiver_account,)
            ).fetchone()

            if receiver is None:
                conn.rollback()
                return None, "Số tài khoản không tồn tại."
            if receiver["id"] == sender["id"]:
                conn.rollback()
                return None, "Không thể chuyển tiền cho chính mình."
            if sender["balance"] < amount:
                conn.rollback()
                return None, "Số dư không đủ để thực hiện giao dịch."

            s_old, r_old = sender["balance"], receiver["balance"]
            s_new, r_new = s_old - amount, r_old + amount
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            data = tx_payload(sender["id"], receiver["id"], amount,
                              s_old, s_new, r_old, r_new, timestamp)
            tx_hash = hash_transaction(data)
            signature = sign_data(data, sender["private_key"])

            conn.execute("UPDATE users SET balance=? WHERE id=?", (s_new, sender["id"]))
            conn.execute("UPDATE users SET balance=? WHERE id=?", (r_new, receiver["id"]))
            cur = conn.execute(
                """INSERT INTO transactions(
                       sender_id, receiver_id, amount, sender_old_balance, sender_new_balance,
                       receiver_old_balance, receiver_new_balance, timestamp,
                       transaction_hash, signature
                   ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (sender["id"], receiver["id"], amount, s_old, s_new,
                 r_old, r_new, timestamp, tx_hash, signature)
            )
            tx_id = cur.lastrowid
            conn.commit()
            return tx_id, None
        except Exception as e:
            conn.rollback()
            return None, f"Lỗi hệ thống: {e}"
        finally:
            conn.close()

    @staticmethod
    def transactions(user_id, direction="all", limit=None):
        sql = """
            SELECT t.*, s.username AS sender_name, s.account_number AS sender_acc,
                        r.username AS receiver_name, r.account_number AS receiver_acc
            FROM transactions t
            JOIN users s ON s.id = t.sender_id
            JOIN users r ON r.id = t.receiver_id
        """
        if direction == "out":
            sql += " WHERE t.sender_id = ?"
            params = (user_id,)
        elif direction == "in":
            sql += " WHERE t.receiver_id = ?"
            params = (user_id,)
        else:
            sql += " WHERE t.sender_id = ? OR t.receiver_id = ?"
            params = (user_id, user_id)
        sql += " ORDER BY t.id DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        conn = get_connection()
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return rows

    @staticmethod
    def transaction(tx_id):
        conn = get_connection()
        row = conn.execute(
            """SELECT t.*, s.username AS sender_name, s.account_number AS sender_acc,
                          r.username AS receiver_name, r.account_number AS receiver_acc
               FROM transactions t
               JOIN users s ON s.id = t.sender_id
               JOIN users r ON r.id = t.receiver_id
               WHERE t.id=?""", (tx_id,)
        ).fetchone()
        conn.close()
        return row

    @staticmethod
    def verify(tx_id):
        """-> (hash_ok, signature_ok)"""
        conn = get_connection()
        tx = conn.execute("SELECT * FROM transactions WHERE id=?", (tx_id,)).fetchone()
        sender = conn.execute("SELECT public_key FROM users WHERE id=?", (tx["sender_id"],)).fetchone()
        conn.close()
        data = tx_payload(tx["sender_id"], tx["receiver_id"], tx["amount"],
                          tx["sender_old_balance"], tx["sender_new_balance"],
                          tx["receiver_old_balance"], tx["receiver_new_balance"], tx["timestamp"])
        hash_ok = hash_transaction(data) == tx["transaction_hash"]
        sig_ok = verify_signature(data, tx["signature"], sender["public_key"])
        return hash_ok, sig_ok

    @staticmethod
    def tamper(tx_id, extra=1_000_000):
        """Demo: sửa số tiền trong DB nhưng giữ nguyên chữ ký."""
        conn = get_connection()
        tx = conn.execute("SELECT amount FROM transactions WHERE id=?", (tx_id,)).fetchone()
        conn.execute("UPDATE transactions SET amount=? WHERE id=?", (tx["amount"] + extra, tx_id))
        conn.commit()
        conn.close()


# =====================================================================
# Widget dùng chung
# =====================================================================
class Clickable(QFrame):
    clicked = Signal()

    def __init__(self):
        super().__init__()
        self.setCursor(Qt.PointingHandCursor)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.LeftButton and self.rect().contains(e.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(e)


class AmountEdit(QLineEdit):
    """Ô nhập tiền, tự chèn dấu phẩy ngăn cách hàng nghìn."""
    MAX = 1_000_000_000

    def __init__(self):
        super().__init__()
        self.setPlaceholderText("0")
        self.setObjectName("AmountField")
        self.setAlignment(Qt.AlignLeft)
        self.textEdited.connect(self._format)

    def _format(self, text):
        digits = "".join(c for c in text if c.isdigit())[:10]
        self.setText(f"{int(digits):,}" if digits else "")

    def value(self):
        digits = "".join(c for c in self.text() if c.isdigit())
        return float(int(digits)) if digits else 0.0

    def set_value(self, v):
        self.setText(f"{int(v):,}" if v else "")


class Sheet(QDialog):
    """Bottom sheet kiểu mobile."""

    def __init__(self, parent, title):
        super().__init__(parent.window())
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setModal(True)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        frame = QFrame()
        frame.setObjectName("Sheet")
        outer.addWidget(frame)

        self.body = QVBoxLayout(frame)
        self.body.setContentsMargins(22, 18, 22, 24)
        self.body.setSpacing(12)

        head = QHBoxLayout()
        t = QLabel(title)
        t.setObjectName("SheetTitle")
        close = QPushButton("✕")
        close.setObjectName("IconBtn")
        close.setCursor(Qt.PointingHandCursor)
        close.clicked.connect(self.reject)
        head.addWidget(t)
        head.addStretch()
        head.addWidget(close)
        self.body.addLayout(head)

    def showEvent(self, e):
        super().showEvent(e)
        p = self.parent()
        self.setFixedWidth(p.width())
        self.adjustSize()
        self.move(p.mapToGlobal(QPoint(0, p.height() - self.height())))


def lbl(text="", name=None, wrap=False, align=None):
    w = QLabel(text)
    if name:
        w.setObjectName(name)
    if wrap:
        w.setWordWrap(True)
    if align:
        w.setAlignment(align)
    return w


def btn(text, slot=None, name="Primary"):
    b = QPushButton(text)
    b.setObjectName(name)
    b.setCursor(Qt.PointingHandCursor)
    if slot:
        # bọc lại để Qt không truyền tham số 'checked' vào slot
        b.clicked.connect(lambda _=False, s=slot: s())
    return b


def clear_layout(layout):
    while layout.count():
        item = layout.takeAt(0)
        if item.widget():
            item.widget().deleteLater()
        elif item.layout():
            clear_layout(item.layout())


def scroll_page():
    """-> (page, content_layout). Nội dung cuộn dọc, không cuộn ngang."""
    page = QWidget()
    outer = QVBoxLayout(page)
    outer.setContentsMargins(0, 0, 0, 0)
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setFrameShape(QFrame.NoFrame)
    sa.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    sa.viewport().setAutoFillBackground(False)
    body = QWidget()
    body.setObjectName("ScrollBody")
    lay = QVBoxLayout(body)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(0)
    sa.setWidget(body)
    outer.addWidget(sa)
    return page, lay


def top_bar(title, back_slot=None):
    bar = QHBoxLayout()
    bar.setContentsMargins(20, 18, 20, 6)
    if back_slot:
        b = btn("←", back_slot, "IconBtn")
        bar.addWidget(b)
    bar.addWidget(lbl(title, "PageTitle"))
    bar.addStretch()
    return bar


# =====================================================================
# Ứng dụng chính
# =====================================================================
HOME, TRANSFER, HISTORY, ACCOUNT, DETAIL, RECEIPT = range(6)


class MobileWallet(QMainWindow):
    def __init__(self, height=800):
        super().__init__()
        self.setObjectName("Main")
        self.setWindowTitle("Digital Wallet")
        self.setFixedSize(390, height)

        self.user = None
        self.hide_balance = False
        self.history_filter = "all"
        self.transfer_target = None     # row người nhận đã tìm thấy
        self.detail_tx_id = None

        self.root = QStackedWidget()
        self.setCentralWidget(self.root)
        self.login_page = self.build_login()
        self.register_page = self.build_register()
        self.shell = self.build_shell()
        for p in (self.login_page, self.register_page, self.shell):
            self.root.addWidget(p)

        self.toast_label = lbl("", "Toast", align=Qt.AlignCenter)
        self.toast_label.setParent(self)
        self.toast_label.hide()

        self.root.setCurrentWidget(self.login_page)

    # ---------- tiện ích chung ----------
    def toast(self, text):
        self.toast_label.setText(text)
        self.toast_label.adjustSize()
        self.toast_label.move((self.width() - self.toast_label.width()) // 2, self.height() - 130)
        self.toast_label.show()
        self.toast_label.raise_()
        QTimer.singleShot(2200, self.toast_label.hide)

    def set_error(self, label, text=""):
        label.setText(text)
        label.setVisible(bool(text))

    def field(self, placeholder, password=False):
        f = QLineEdit()
        f.setObjectName("Field")
        f.setPlaceholderText(placeholder)
        if password:
            f.setEchoMode(QLineEdit.Password)
        return f

    def form_box(self, title, widget):
        box = QVBoxLayout()
        box.setSpacing(6)
        box.addWidget(lbl(title, "FieldLabel"))
        box.addWidget(widget)
        return box

    def hero(self, height=None):
        h = QFrame()
        h.setObjectName("Hero")
        if height:
            h.setMinimumHeight(height)
        return h

    # =================================================================
    # LOGIN
    # =================================================================
    def build_login(self):
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        hero = self.hero(250)
        hl = QVBoxLayout(hero)
        hl.setContentsMargins(28, 60, 28, 30)
        hl.addWidget(lbl("🔐  DIGITAL WALLET", "BrandWhite"))
        hl.addSpacing(18)
        hl.addWidget(lbl("Chào mừng trở lại", "HeroTitle"))
        hl.addWidget(lbl("Đăng nhập để quản lý tài khoản và giao dịch được bảo vệ bằng chữ ký số RSA.",
                         "HeroSub", wrap=True))
        hl.addStretch()
        root.addWidget(hero)

        form = QVBoxLayout()
        form.setContentsMargins(24, 24, 24, 24)
        form.setSpacing(14)

        self.login_notice = lbl("", "Notice", wrap=True)
        self.login_notice.hide()
        self.login_acc = self.field("Số tài khoản")
        self.login_pw = self.field("Mật khẩu", True)
        self.login_err = lbl("", "Error", wrap=True)
        self.login_err.hide()
        self.login_pw.returnPressed.connect(self.do_login)

        form.addWidget(self.login_notice)
        form.addLayout(self.form_box("Số tài khoản", self.login_acc))
        form.addLayout(self.form_box("Mật khẩu", self.login_pw))
        form.addWidget(self.login_err)
        form.addSpacing(4)
        form.addWidget(btn("Đăng nhập", self.do_login))
        form.addWidget(btn("Tạo tài khoản mới", self.show_register, "Secondary"))
        form.addStretch()
        root.addLayout(form)
        return page

    def show_login(self, notice="", account=""):
        self.login_acc.setText(account)
        self.login_pw.clear()
        self.set_error(self.login_err)
        self.login_notice.setText(notice)
        self.login_notice.setVisible(bool(notice))
        self.root.setCurrentWidget(self.login_page)

    def do_login(self):
        acc = self.login_acc.text().strip()
        pw = self.login_pw.text()
        if not acc or not pw:
            self.set_error(self.login_err, "Vui lòng nhập số tài khoản và mật khẩu.")
            return
        row = Bank.authenticate(acc, pw)
        if not row:
            self.set_error(self.login_err, "Sai số tài khoản hoặc mật khẩu.")
            return
        self.user = row
        self.hide_balance = False
        self.root.setCurrentWidget(self.shell)
        self.goto(HOME)

    def logout(self):
        self.user = None
        self.show_login()

    # =================================================================
    # REGISTER
    # =================================================================
    def build_register(self):
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(14)

        back = QHBoxLayout()
        back.addWidget(btn("←", self.show_login, "IconBtn"))
        back.addStretch()
        root.addLayout(back)
        root.addWidget(lbl("Tạo tài khoản", "BigTitle"))
        root.addWidget(lbl("Hệ thống sẽ tự tạo số tài khoản và cặp khóa RSA dùng để ký giao dịch của bạn.",
                           "Muted", wrap=True))
        root.addSpacing(6)

        self.reg_name = self.field("Tên hiển thị")
        self.reg_pw = self.field("Tối thiểu 6 ký tự", True)
        self.reg_pw2 = self.field("Nhập lại mật khẩu", True)
        self.reg_err = lbl("", "Error", wrap=True)
        self.reg_err.hide()

        root.addLayout(self.form_box("Tên hiển thị", self.reg_name))
        root.addLayout(self.form_box("Mật khẩu", self.reg_pw))
        root.addLayout(self.form_box("Xác nhận mật khẩu", self.reg_pw2))
        root.addWidget(self.reg_err)
        root.addSpacing(4)
        root.addWidget(btn("Đăng ký", self.do_register))
        root.addStretch()
        return page

    def show_register(self):
        for f in (self.reg_name, self.reg_pw, self.reg_pw2):
            f.clear()
        self.set_error(self.reg_err)
        self.root.setCurrentWidget(self.register_page)

    def do_register(self):
        name = self.reg_name.text().strip()
        pw, pw2 = self.reg_pw.text(), self.reg_pw2.text()
        if not name or not pw:
            return self.set_error(self.reg_err, "Vui lòng nhập đầy đủ thông tin.")
        if len(pw) < 6:
            return self.set_error(self.reg_err, "Mật khẩu phải có ít nhất 6 ký tự.")
        if pw != pw2:
            return self.set_error(self.reg_err, "Hai mật khẩu không giống nhau.")
        try:
            acc = Bank.register(name, pw)
        except Exception as e:
            return self.set_error(self.reg_err, f"Không thể tạo tài khoản: {e}")
        self.show_login(f"✓ Tạo tài khoản thành công!\nSố tài khoản của bạn: {acc}\nHãy ghi nhớ để đăng nhập.", acc)

    # =================================================================
    # SHELL: các tab + thanh điều hướng dưới
    # =================================================================
    def build_shell(self):
        shell = QWidget()
        lay = QVBoxLayout(shell)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        self.inner = QStackedWidget()
        self.home_page = self.build_home()
        self.transfer_page = self.build_transfer()
        self.history_page = self.build_history()
        self.account_page = self.build_account()
        self.detail_page = self.build_detail()
        self.receipt_page = self.build_receipt()
        for p in (self.home_page, self.transfer_page, self.history_page,
                  self.account_page, self.detail_page, self.receipt_page):
            self.inner.addWidget(p)
        lay.addWidget(self.inner, 1)

        self.nav = QFrame()
        self.nav.setObjectName("NavBar")
        nl = QHBoxLayout(self.nav)
        nl.setContentsMargins(8, 6, 8, 8)
        nl.setSpacing(0)
        self.nav_group = QButtonGroup(self)
        self.nav_buttons = []
        for i, (icon, text) in enumerate([("🏠", "Trang chủ"), ("💸", "Chuyển tiền"),
                                          ("📜", "Lịch sử"), ("👤", "Tài khoản")]):
            b = QPushButton(f"{icon}\n{text}")
            b.setObjectName("NavBtn")
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            self.nav_group.addButton(b, i)
            self.nav_buttons.append(b)
            nl.addWidget(b)
        self.nav_group.idClicked.connect(self.goto)
        lay.addWidget(self.nav)
        return shell

    def goto(self, index):
        if index == HOME:
            self.refresh_home()
        elif index == TRANSFER:
            self.reset_transfer()
        elif index == HISTORY:
            self.refresh_history()
        elif index == ACCOUNT:
            self.refresh_account()
        self.inner.setCurrentIndex(index)
        self.nav.setVisible(index <= ACCOUNT)
        if index <= ACCOUNT:
            self.nav_buttons[index].setChecked(True)

    def reload_user(self):
        self.user = Bank.get_user(self.user["id"])

    # ---------- một dòng giao dịch ----------
    def tx_row(self, row):
        outgoing = row["sender_id"] == self.user["id"]
        partner = row["receiver_name"] if outgoing else row["sender_name"]

        w = Clickable()
        w.setObjectName("TxRow")
        h = QHBoxLayout(w)
        h.setContentsMargins(4, 10, 4, 10)
        h.setSpacing(12)

        icon = lbl("↑" if outgoing else "↓", "TxIconOut" if outgoing else "TxIconIn", align=Qt.AlignCenter)
        icon.setFixedSize(42, 42)
        h.addWidget(icon)

        mid = QVBoxLayout()
        mid.setSpacing(2)
        mid.addWidget(lbl(("Chuyển đến " if outgoing else "Nhận từ ") + partner, "TxName"))
        mid.addWidget(lbl(row["timestamp"], "TxTime"))
        h.addLayout(mid, 1)

        sign = "-" if outgoing else "+"
        h.addWidget(lbl(f"{sign}{row['amount']:,.0f}", "AmtOut" if outgoing else "AmtIn"))

        w.clicked.connect(lambda tx_id=row["id"]: self.open_detail(tx_id))
        return w

    def fill_tx_list(self, layout, rows, empty_text):
        clear_layout(layout)
        if not rows:
            layout.addWidget(lbl(empty_text, "Empty", wrap=True, align=Qt.AlignCenter))
            return
        for i, r in enumerate(rows):
            layout.addWidget(self.tx_row(r))
            if i < len(rows) - 1:
                sep = QFrame()
                sep.setObjectName("Sep")
                sep.setFixedHeight(1)
                layout.addWidget(sep)

    # =================================================================
    # HOME
    # =================================================================
    def build_home(self):
        page, lay = scroll_page()

        hero = self.hero()
        hl = QVBoxLayout(hero)
        hl.setContentsMargins(22, 34, 22, 26)
        hl.setSpacing(4)

        top = QHBoxLayout()
        self.avatar_home = lbl("", "Avatar", align=Qt.AlignCenter)
        self.avatar_home.setFixedSize(44, 44)
        top.addWidget(self.avatar_home)
        who = QVBoxLayout()
        who.setSpacing(0)
        who.addWidget(lbl("Xin chào,", "HeroSub"))
        self.home_name = lbl("", "HeroName")
        who.addWidget(self.home_name)
        top.addLayout(who, 1)
        self.eye_btn = btn("👁", self.toggle_balance, "GlassBtn")
        top.addWidget(self.eye_btn)
        hl.addLayout(top)

        hl.addSpacing(16)
        hl.addWidget(lbl("SỐ DƯ KHẢ DỤNG", "SmallCaps"))
        self.home_balance = lbl("", "BalanceBig")
        hl.addWidget(self.home_balance)

        acc_row = QHBoxLayout()
        self.home_acc = lbl("", "HeroSub")
        acc_row.addWidget(self.home_acc)
        acc_row.addStretch()
        acc_row.addWidget(btn("Sao chép", self.copy_account, "GlassBtn"))
        hl.addLayout(acc_row)
        lay.addWidget(hero)

        body = QVBoxLayout()
        body.setContentsMargins(18, 16, 18, 18)
        body.setSpacing(14)

        actions = QFrame()
        actions.setObjectName("Card")
        al = QHBoxLayout(actions)
        al.setContentsMargins(8, 14, 8, 14)
        for icon, text, slot in [("💰", "Nạp tiền", self.open_deposit),
                                 ("💸", "Chuyển tiền", lambda: self.goto(TRANSFER)),
                                 ("📜", "Lịch sử", lambda: self.goto(HISTORY))]:
            al.addWidget(self.action_tile(icon, text, slot))
        body.addWidget(actions)

        head = QHBoxLayout()
        head.addWidget(lbl("Giao dịch gần đây", "SectionTitle"))
        head.addStretch()
        head.addWidget(btn("Xem tất cả", lambda: self.goto(HISTORY), "Link"))
        body.addLayout(head)

        card = QFrame()
        card.setObjectName("Card")
        self.home_tx_layout = QVBoxLayout(card)
        self.home_tx_layout.setContentsMargins(14, 6, 14, 6)
        self.home_tx_layout.setSpacing(0)
        body.addWidget(card)

        sec = QFrame()
        sec.setObjectName("InfoCard")
        sl = QVBoxLayout(sec)
        sl.setContentsMargins(16, 14, 16, 14)
        sl.setSpacing(4)
        sl.addWidget(lbl("🔐 Bảo mật bằng chữ ký số", "InfoTitle"))
        sl.addWidget(lbl("Mỗi giao dịch được băm SHA-256 và ký bằng khóa riêng RSA. "
                         "Bạn có thể xác minh tính toàn vẹn ở mục Lịch sử.", "InfoText", wrap=True))
        body.addWidget(sec)

        lay.addLayout(body)
        lay.addStretch()
        return page

    def action_tile(self, icon, text, slot):
        t = Clickable()
        t.setObjectName("Tile")
        v = QVBoxLayout(t)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)
        i = lbl(icon, "TileIcon", align=Qt.AlignCenter)
        i.setFixedSize(52, 52)
        v.addWidget(i, 0, Qt.AlignHCenter)
        v.addWidget(lbl(text, "TileText", align=Qt.AlignCenter))
        t.clicked.connect(slot)
        return t

    def refresh_home(self):
        self.reload_user()
        u = self.user
        self.avatar_home.setText(u["username"][:1].upper())
        self.home_name.setText(u["username"])
        self.home_acc.setText(f"STK  {u['account_number']}")
        self.apply_balance_visibility()
        rows = Bank.transactions(u["id"], limit=5)
        self.fill_tx_list(self.home_tx_layout, rows, "Chưa có giao dịch nào.")

    def apply_balance_visibility(self):
        self.home_balance.setText("••••••••" if self.hide_balance else money(self.user["balance"]))
        self.eye_btn.setText("🙈" if self.hide_balance else "👁")

    def toggle_balance(self):
        self.hide_balance = not self.hide_balance
        self.apply_balance_visibility()

    def copy_account(self):
        QApplication.clipboard().setText(self.user["account_number"])
        self.toast("Đã sao chép số tài khoản")

    # ---------- nạp tiền ----------
    def open_deposit(self):
        sheet = Sheet(self, "Nạp tiền")
        sheet.body.addWidget(lbl("Nhập số tiền muốn nạp vào tài khoản", "Muted"))
        amount = AmountEdit()
        sheet.body.addWidget(amount)
        sheet.body.addLayout(self.chips(amount))
        err = lbl("", "Error", wrap=True)
        err.hide()
        sheet.body.addWidget(err)

        def confirm():
            v = amount.value()
            if v <= 0:
                return self.set_error(err, "Vui lòng nhập số tiền hợp lệ.")
            if v > AmountEdit.MAX:
                return self.set_error(err, "Số tiền tối đa mỗi lần là 1,000,000,000 VNĐ.")
            Bank.deposit(self.user["id"], v)
            sheet.accept()
            self.refresh_home()
            self.toast(f"Đã nạp {money(v)}")

        sheet.body.addWidget(btn("Nạp tiền", confirm))
        sheet.exec()

    def chips(self, amount_edit):
        row = QHBoxLayout()
        row.setSpacing(8)
        for label, val in [("100K", 100_000), ("500K", 500_000), ("1 triệu", 1_000_000), ("5 triệu", 5_000_000)]:
            c = btn(label, None, "Chip")
            c.clicked.connect(lambda _=False, v=val: amount_edit.set_value(v))
            row.addWidget(c)
        return row

    # =================================================================
    # TRANSFER
    # =================================================================
    def build_transfer(self):
        page, lay = scroll_page()
        lay.addLayout(top_bar("Chuyển tiền"))

        body = QVBoxLayout()
        body.setContentsMargins(18, 10, 18, 18)
        body.setSpacing(14)

        card = QFrame()
        card.setObjectName("Card")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(16, 16, 16, 16)
        cl.setSpacing(10)

        self.tr_acc = self.field("Nhập số tài khoản người nhận")
        self.tr_acc.textChanged.connect(self.lookup_receiver)
        cl.addLayout(self.form_box("Đến tài khoản", self.tr_acc))
        self.tr_name = lbl("", "Recipient")
        self.tr_name.hide()
        cl.addWidget(self.tr_name)
        body.addWidget(card)

        card2 = QFrame()
        card2.setObjectName("Card")
        c2 = QVBoxLayout(card2)
        c2.setContentsMargins(16, 16, 16, 16)
        c2.setSpacing(10)
        c2.addWidget(lbl("Số tiền (VNĐ)", "FieldLabel"))
        self.tr_amount = AmountEdit()
        c2.addWidget(self.tr_amount)
        self.tr_balance = lbl("", "Muted")
        c2.addWidget(self.tr_balance)
        c2.addLayout(self.chips(self.tr_amount))
        body.addWidget(card2)

        self.tr_err = lbl("", "Error", wrap=True)
        self.tr_err.hide()
        body.addWidget(self.tr_err)
        body.addWidget(btn("Tiếp tục", self.review_transfer))
        body.addWidget(lbl("🔐 Giao dịch sẽ được ký số bằng khóa RSA của bạn trước khi lưu.",
                           "Muted", wrap=True))
        lay.addLayout(body)
        lay.addStretch()
        return page

    def reset_transfer(self):
        self.reload_user()
        self.tr_acc.clear()
        self.tr_amount.clear()
        self.tr_name.hide()
        self.transfer_target = None
        self.set_error(self.tr_err)
        self.tr_balance.setText(f"Số dư khả dụng: {money(self.user['balance'])}")

    def lookup_receiver(self, text):
        text = text.strip()
        self.transfer_target = None
        if len(text) < 8:
            self.tr_name.hide()
            return
        if text == self.user["account_number"]:
            self.tr_name.setText("✗ Không thể chuyển cho chính mình")
            self.tr_name.setProperty("ok", False)
        else:
            row = Bank.find_account(text)
            if row:
                self.transfer_target = row
                self.tr_name.setText(f"✓ {row['username']}")
                self.tr_name.setProperty("ok", True)
            else:
                self.tr_name.setText("✗ Không tìm thấy tài khoản")
                self.tr_name.setProperty("ok", False)
        self.tr_name.style().unpolish(self.tr_name)
        self.tr_name.style().polish(self.tr_name)
        self.tr_name.show()

    def review_transfer(self):
        amount = self.tr_amount.value()
        self.reload_user()
        if self.transfer_target is None:
            return self.set_error(self.tr_err, "Vui lòng nhập số tài khoản người nhận hợp lệ.")
        if amount <= 0:
            return self.set_error(self.tr_err, "Vui lòng nhập số tiền cần chuyển.")
        if amount > AmountEdit.MAX:
            return self.set_error(self.tr_err, "Số tiền tối đa mỗi lần là 1,000,000,000 VNĐ.")
        if amount > self.user["balance"]:
            return self.set_error(self.tr_err, "Số dư không đủ để thực hiện giao dịch.")
        self.set_error(self.tr_err)
        self.confirm_transfer(self.transfer_target, amount)

    def confirm_transfer(self, target, amount):
        sheet = Sheet(self, "Xác nhận chuyển tiền")
        sheet.body.addWidget(lbl(money(amount), "ConfirmAmount", align=Qt.AlignCenter))
        for k, v in [("Người nhận", target["username"]),
                     ("Số tài khoản", target["account_number"]),
                     ("Phí giao dịch", "Miễn phí")]:
            r = QHBoxLayout()
            r.addWidget(lbl(k, "Muted"))
            r.addStretch()
            r.addWidget(lbl(v, "Value"))
            sheet.body.addLayout(r)

        pw = self.field("Nhập mật khẩu để xác nhận", True)
        err = lbl("", "Error", wrap=True)
        err.hide()
        sheet.body.addWidget(pw)
        sheet.body.addWidget(err)

        def submit():
            if hash_password(pw.text()) != self.user["password"]:
                return self.set_error(err, "Mật khẩu không đúng.")
            tx_id, error = Bank.transfer(self.user["id"], target["account_number"], amount)
            if error:
                return self.set_error(err, error)
            sheet.accept()
            self.open_receipt(tx_id)

        pw.returnPressed.connect(submit)
        sheet.body.addWidget(btn("🔏  Ký & Chuyển tiền", submit))
        sheet.exec()

    # ---------- biên lai ----------
    def build_receipt(self):
        page, lay = scroll_page()
        body = QVBoxLayout()
        body.setContentsMargins(22, 50, 22, 22)
        body.setSpacing(12)

        ok = lbl("✓", "SuccessCircle", align=Qt.AlignCenter)
        ok.setFixedSize(76, 76)
        body.addWidget(ok, 0, Qt.AlignHCenter)
        body.addWidget(lbl("Chuyển tiền thành công", "BigTitle", align=Qt.AlignCenter))
        self.rc_amount = lbl("", "ReceiptAmount", align=Qt.AlignCenter)
        body.addWidget(self.rc_amount)

        card = QFrame()
        card.setObjectName("Card")
        self.rc_grid = QVBoxLayout(card)
        self.rc_grid.setContentsMargins(16, 14, 16, 14)
        self.rc_grid.setSpacing(10)
        body.addWidget(card)

        body.addSpacing(6)
        body.addWidget(btn("Xem chi tiết & xác minh", lambda: self.open_detail(self.detail_tx_id), "Secondary"))
        body.addWidget(btn("Xong", lambda: self.goto(HOME)))
        lay.addLayout(body)
        lay.addStretch()
        return page

    def kv_row(self, layout, key, value, value_name="Value"):
        r = QHBoxLayout()
        r.addWidget(lbl(key, "Muted"))
        r.addStretch()
        r.addWidget(lbl(value, value_name))
        layout.addLayout(r)

    def open_receipt(self, tx_id):
        tx = Bank.transaction(tx_id)
        self.detail_tx_id = tx_id
        self.rc_amount.setText(money(tx["amount"]))
        clear_layout(self.rc_grid)
        self.kv_row(self.rc_grid, "Người nhận", tx["receiver_name"])
        self.kv_row(self.rc_grid, "Số tài khoản", tx["receiver_acc"])
        self.kv_row(self.rc_grid, "Thời gian", tx["timestamp"])
        self.kv_row(self.rc_grid, "Mã giao dịch", f"#{tx['id']}")
        self.kv_row(self.rc_grid, "SHA-256", short_hash(tx["transaction_hash"], 8, 6), "Mono")
        self.kv_row(self.rc_grid, "Chữ ký RSA", "Đã ký ✓", "ValueOk")
        self.goto(RECEIPT)

    # =================================================================
    # HISTORY
    # =================================================================
    def build_history(self):
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addLayout(top_bar("Lịch sử giao dịch"))

        chips = QHBoxLayout()
        chips.setContentsMargins(18, 4, 18, 8)
        chips.setSpacing(8)
        self.filter_group = QButtonGroup(self)
        self.filter_btns = {}
        for key, text in [("all", "Tất cả"), ("in", "Đã nhận"), ("out", "Đã chuyển")]:
            b = btn(text, None, "Chip")
            b.setCheckable(True)
            self.filter_group.addButton(b)
            self.filter_btns[key] = b
            b.clicked.connect(lambda _=False, k=key: self.set_filter(k))
            chips.addWidget(b)
        chips.addStretch()
        root.addLayout(chips)

        sp, lay = scroll_page()
        card = QFrame()
        card.setObjectName("Card")
        self.history_layout = QVBoxLayout(card)
        self.history_layout.setContentsMargins(14, 6, 14, 6)
        self.history_layout.setSpacing(0)
        wrap = QVBoxLayout()
        wrap.setContentsMargins(18, 4, 18, 18)
        wrap.addWidget(card)
        lay.addLayout(wrap)
        lay.addStretch()
        root.addWidget(sp, 1)
        return page

    def set_filter(self, key):
        self.history_filter = key
        self.refresh_history()

    def refresh_history(self):
        self.filter_btns[self.history_filter].setChecked(True)
        rows = Bank.transactions(self.user["id"], self.history_filter)
        self.fill_tx_list(self.history_layout, rows, "Không có giao dịch nào.")

    # =================================================================
    # DETAIL + XÁC MINH
    # =================================================================
    def build_detail(self):
        page, lay = scroll_page()
        lay.addLayout(top_bar("Chi tiết giao dịch", lambda: self.goto(HISTORY)))

        body = QVBoxLayout()
        body.setContentsMargins(18, 8, 18, 18)
        body.setSpacing(14)

        card = QFrame()
        card.setObjectName("Card")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(16, 18, 16, 16)
        cl.setSpacing(10)
        self.dt_amount = lbl("", "ReceiptAmount", align=Qt.AlignCenter)
        self.dt_type = lbl("", "Muted", align=Qt.AlignCenter)
        cl.addWidget(self.dt_amount)
        cl.addWidget(self.dt_type)
        cl.addSpacing(6)
        self.dt_grid = QVBoxLayout()
        self.dt_grid.setSpacing(10)
        cl.addLayout(self.dt_grid)
        body.addWidget(card)

        self.verify_box = QFrame()
        self.verify_box.setObjectName("VerifyBox")
        vl = QVBoxLayout(self.verify_box)
        vl.setContentsMargins(16, 14, 16, 14)
        self.verify_title = lbl("", "VerifyTitle")
        self.verify_text = lbl("", "VerifyText", wrap=True)
        vl.addWidget(self.verify_title)
        vl.addWidget(self.verify_text)
        self.verify_box.hide()
        body.addWidget(self.verify_box)

        body.addWidget(btn("🔍  Xác minh chữ ký số", self.run_verify))
        body.addWidget(btn("🧪 Demo: sửa số tiền trong database", self.run_tamper, "Link"))
        lay.addLayout(body)
        lay.addStretch()
        return page

    def open_detail(self, tx_id):
        self.detail_tx_id = tx_id
        self.verify_box.hide()
        self.render_detail()
        self.goto(DETAIL)

    def render_detail(self):
        tx = Bank.transaction(self.detail_tx_id)
        outgoing = tx["sender_id"] == self.user["id"]
        self.dt_amount.setText(("-" if outgoing else "+") + money(tx["amount"]))
        self.dt_amount.setObjectName("AmtOutBig" if outgoing else "AmtInBig")
        self.dt_amount.style().unpolish(self.dt_amount)
        self.dt_amount.style().polish(self.dt_amount)
        self.dt_type.setText("Chuyển tiền đi" if outgoing else "Tiền nhận về")
        clear_layout(self.dt_grid)
        self.kv_row(self.dt_grid, "Mã giao dịch", f"#{tx['id']}")
        self.kv_row(self.dt_grid, "Người gửi", f"{tx['sender_name']} ({tx['sender_acc']})")
        self.kv_row(self.dt_grid, "Người nhận", f"{tx['receiver_name']} ({tx['receiver_acc']})")
        self.kv_row(self.dt_grid, "Thời gian", tx["timestamp"])
        self.kv_row(self.dt_grid, "SHA-256", short_hash(tx["transaction_hash"], 10, 8), "Mono")
        self.kv_row(self.dt_grid, "Chữ ký RSA", short_hash(tx["signature"], 10, 6), "Mono")

    def run_verify(self):
        hash_ok, sig_ok = Bank.verify(self.detail_tx_id)
        valid = hash_ok and sig_ok
        self.verify_box.setProperty("valid", valid)
        self.verify_box.style().unpolish(self.verify_box)
        self.verify_box.style().polish(self.verify_box)
        if valid:
            self.verify_title.setText("✓ GIAO DỊCH HỢP LỆ")
            self.verify_text.setText("✓ SHA-256 hash khớp\n✓ Chữ ký RSA hợp lệ\n✓ Dữ liệu chưa bị thay đổi")
        else:
            self.verify_title.setText("✗ PHÁT HIỆN DỮ LIỆU BỊ THAY ĐỔI")
            self.verify_text.setText(f"{'✓' if hash_ok else '✗'} SHA-256 hash\n"
                                     f"{'✓' if sig_ok else '✗'} Chữ ký RSA\n"
                                     "Giao dịch không còn khớp với phiên đã ký.")
        self.verify_box.show()

    def run_tamper(self):
        Bank.tamper(self.detail_tx_id)
        self.verify_box.hide()
        self.render_detail()
        self.toast("Đã sửa số tiền (+1,000,000). Hãy bấm Xác minh.")

    # =================================================================
    # ACCOUNT
    # =================================================================
    def build_account(self):
        page, lay = scroll_page()
        lay.addLayout(top_bar("Tài khoản"))

        body = QVBoxLayout()
        body.setContentsMargins(18, 10, 18, 18)
        body.setSpacing(14)

        prof = QFrame()
        prof.setObjectName("Card")
        pl = QVBoxLayout(prof)
        pl.setContentsMargins(16, 22, 16, 18)
        pl.setSpacing(6)
        self.avatar_acc = lbl("", "AvatarBig", align=Qt.AlignCenter)
        self.avatar_acc.setFixedSize(72, 72)
        pl.addWidget(self.avatar_acc, 0, Qt.AlignHCenter)
        self.acc_name = lbl("", "BigTitle", align=Qt.AlignCenter)
        self.acc_number = lbl("", "Muted", align=Qt.AlignCenter)
        pl.addWidget(self.acc_name)
        pl.addWidget(self.acc_number)
        body.addWidget(prof)

        info = QFrame()
        info.setObjectName("Card")
        self.acc_info = QVBoxLayout(info)
        self.acc_info.setContentsMargins(16, 14, 16, 14)
        self.acc_info.setSpacing(10)
        body.addWidget(info)

        body.addWidget(btn("Đăng xuất", self.logout, "Danger"))
        lay.addLayout(body)
        lay.addStretch()
        return page

    def refresh_account(self):
        self.reload_user()
        u = self.user
        self.avatar_acc.setText(u["username"][:1].upper())
        self.acc_name.setText(u["username"])
        self.acc_number.setText(f"STK {u['account_number']}")
        fingerprint = hashlib.sha256(u["public_key"].encode()).hexdigest()[:16].upper()
        clear_layout(self.acc_info)
        self.kv_row(self.acc_info, "Số dư", money(u["balance"]))
        self.kv_row(self.acc_info, "Khóa ký số", "RSA-2048")
        self.kv_row(self.acc_info, "Mã băm", "SHA-256")
        self.kv_row(self.acc_info, "Vân tay khóa công khai", fingerprint, "Mono")


# =====================================================================
# Style
# =====================================================================
STYLE = """
* { font-family: "Segoe UI", "SF Pro Text", "Roboto", sans-serif; font-size: 14px; color: #141B2D; }
QLabel { background: transparent; }
QMainWindow#Main { background: #F2F5FB; }
QDialog { background: transparent; }
QScrollArea { background: transparent; border: none; }
QWidget#ScrollBody { background: transparent; }
QScrollBar:vertical { width: 0px; }

/* ----- hero ----- */
QFrame#Hero {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0F2A6B, stop:1 #2F6BFF);
    border-bottom-left-radius: 28px; border-bottom-right-radius: 28px;
}
QFrame#Hero QLabel { color: white; }
QLabel#BrandWhite { color: white; font-size: 16px; font-weight: 800; letter-spacing: 1px; }
QLabel#HeroTitle { color: white; font-size: 28px; font-weight: 800; }
QLabel#HeroSub { color: rgba(255,255,255,0.78); font-size: 13px; }
QLabel#HeroName { color: white; font-size: 18px; font-weight: 700; }
QLabel#SmallCaps { color: rgba(255,255,255,0.7); font-size: 11px; font-weight: 700; letter-spacing: 1.5px; }
QLabel#BalanceBig { color: white; font-size: 32px; font-weight: 800; }
QLabel#Avatar { background: rgba(255,255,255,0.22); color: white; font-weight: 800; font-size: 18px; border-radius: 22px; }
QPushButton#GlassBtn {
    background: rgba(255,255,255,0.18); color: white; border: none;
    border-radius: 14px; padding: 6px 12px; font-weight: 600; font-size: 12px;
}
QPushButton#GlassBtn:hover { background: rgba(255,255,255,0.3); }

/* ----- text ----- */
QLabel#BigTitle { font-size: 24px; font-weight: 800; }
QLabel#PageTitle { font-size: 22px; font-weight: 800; }
QLabel#SectionTitle { font-size: 16px; font-weight: 700; }
QLabel#FieldLabel { color: #4A5672; font-size: 12px; font-weight: 700; }
QLabel#Muted { color: #6B7690; font-size: 13px; }
QLabel#Value { font-weight: 600; }
QLabel#ValueOk { font-weight: 700; color: #12A36B; }
QLabel#Mono { font-family: "Consolas", "Menlo", monospace; font-size: 12px; color: #4A5672; }
QLabel#Empty { color: #8A94AA; padding: 28px 10px; }
QLabel#Error { color: #D93040; background: #FDECEE; border-radius: 10px; padding: 10px 12px; font-size: 13px; }
QLabel#Notice { color: #0B7A52; background: #E3F7EE; border-radius: 10px; padding: 10px 12px; font-size: 13px; }
QLabel#Recipient { font-weight: 700; padding: 2px 2px; }
QLabel#Recipient[ok="true"] { color: #12A36B; }
QLabel#Recipient[ok="false"] { color: #D93040; }
QLabel#ConfirmAmount { font-size: 28px; font-weight: 800; color: #1F4FD1; padding: 6px 0 10px 0; }
QLabel#ReceiptAmount, QLabel#AmtInBig, QLabel#AmtOutBig { font-size: 28px; font-weight: 800; }
QLabel#AmtInBig { color: #12A36B; }
QLabel#AmtOutBig { color: #141B2D; }
QLabel#SuccessCircle { background: #E3F7EE; color: #12A36B; font-size: 38px; font-weight: 800; border-radius: 38px; }

/* ----- cards ----- */
QFrame#Card { background: white; border-radius: 18px; }
QFrame#InfoCard { background: #E9F0FF; border-radius: 16px; }
QLabel#InfoTitle { color: #1F4FD1; font-weight: 700; }
QLabel#InfoText { color: #41557F; font-size: 12px; }
QFrame#Sep { background: #EEF1F6; border: none; }
QFrame#Sheet { background: white; border-top-left-radius: 26px; border-top-right-radius: 26px; }
QLabel#SheetTitle { font-size: 18px; font-weight: 800; }

/* ----- actions ----- */
QFrame#Tile { background: transparent; }
QLabel#TileIcon { background: #E9F0FF; border-radius: 26px; font-size: 22px; }
QLabel#TileText { font-size: 12px; font-weight: 600; }

/* ----- transactions ----- */
QFrame#TxRow { background: transparent; }
QLabel#TxIconIn { background: #E3F7EE; color: #12A36B; border-radius: 21px; font-size: 18px; font-weight: 800; }
QLabel#TxIconOut { background: #FDECEE; color: #D93040; border-radius: 21px; font-size: 18px; font-weight: 800; }
QLabel#TxName { font-weight: 600; }
QLabel#TxTime { color: #8A94AA; font-size: 12px; }
QLabel#AmtIn { color: #12A36B; font-weight: 700; }
QLabel#AmtOut { color: #141B2D; font-weight: 700; }

/* ----- verify ----- */
QFrame#VerifyBox { border-radius: 16px; }
QFrame#VerifyBox[valid="true"]  { background: #E3F7EE; }
QFrame#VerifyBox[valid="false"] { background: #FDECEE; }
QFrame#VerifyBox[valid="true"]  QLabel#VerifyTitle { color: #0B7A52; }
QFrame#VerifyBox[valid="false"] QLabel#VerifyTitle { color: #D93040; }
QLabel#VerifyTitle { font-weight: 800; font-size: 14px; }
QLabel#VerifyText { color: #41557F; font-size: 13px; }

/* ----- inputs ----- */
QLineEdit#Field, QLineEdit#AmountField {
    background: white; border: 1.5px solid #DCE2EE; border-radius: 14px; padding: 13px 14px;
}
QLineEdit#Field:focus, QLineEdit#AmountField:focus { border: 1.5px solid #2F6BFF; }
QLineEdit#AmountField { font-size: 24px; font-weight: 800; background: #F7F9FD; }
QFrame#Sheet QLineEdit#Field { background: #F7F9FD; }
QFrame#Card QLineEdit#Field { background: #F7F9FD; }

/* ----- buttons ----- */
QPushButton#Primary {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1F4FD1, stop:1 #2F6BFF);
    color: white; border: none; border-radius: 14px; padding: 14px; font-weight: 700; font-size: 15px;
}
QPushButton#Primary:hover { background: #1A43B5; }
QPushButton#Secondary {
    background: #E9F0FF; color: #1F4FD1; border: none; border-radius: 14px; padding: 14px; font-weight: 700; font-size: 15px;
}
QPushButton#Secondary:hover { background: #DCE8FF; }
QPushButton#Danger {
    background: #FDECEE; color: #D93040; border: none; border-radius: 14px; padding: 14px; font-weight: 700; font-size: 15px;
}
QPushButton#Danger:hover { background: #FAD9DD; }
QPushButton#Link { background: transparent; color: #2F6BFF; border: none; font-weight: 600; padding: 6px; }
QPushButton#Link:hover { color: #1A43B5; }
QPushButton#IconBtn {
    background: white; border: none; border-radius: 18px; min-width: 36px; max-width: 36px;
    min-height: 36px; max-height: 36px; font-size: 16px; font-weight: 700;
}
QPushButton#IconBtn:hover { background: #E9F0FF; }
QPushButton#Chip {
    background: white; color: #41557F; border: 1.5px solid #DCE2EE; border-radius: 16px;
    padding: 7px 14px; font-weight: 600; font-size: 13px;
}
QPushButton#Chip:hover { background: #F0F4FF; }
QPushButton#Chip:checked { background: #1F4FD1; color: white; border: 1.5px solid #1F4FD1; }

/* ----- bottom nav ----- */
QFrame#NavBar { background: white; border-top: 1px solid #E6EAF2; }
QPushButton#NavBtn {
    background: transparent; border: none; color: #8A94AA; font-size: 11px; font-weight: 600; padding: 6px 0;
}
QPushButton#NavBtn:checked { color: #1F4FD1; font-weight: 800; }

/* ----- toast ----- */
QLabel#Toast { background: #141B2D; color: white; border-radius: 18px; padding: 10px 18px; font-size: 13px; }
"""


def main():
    init_db()
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    avail = app.primaryScreen().availableGeometry().height()
    window = MobileWallet(height=min(800, avail - 60))
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
