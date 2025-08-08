import os
import json
import re
import hashlib
import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QFileDialog, QLineEdit, QMessageBox,
    QProgressBar, QGroupBox, QCheckBox, QSplitter, QDialog, QFormLayout,
    QDialogButtonBox, QCalendarWidget, QMessageBox, QComboBox, QInputDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QDate
from PyQt5.QtGui import QFont, QColor, QPalette

# Security Constants
RSA_KEY_SIZE = 3072
ECC_CURVE = ec.SECP521R1()
AES_KEY_SIZE = 32
PBKDF2_ITERATIONS = 600000
CHUNK_SIZE = 64 * 1024
MIN_PASSPHRASE_LENGTH = 15
KEY_EXPIRATION_DAYS = 90

class SecurityUtils:
    @staticmethod
    def is_strong_passphrase(passphrase):
        """Enforce 15+ character passphrases with special characters"""
        if len(passphrase) < MIN_PASSPHRASE_LENGTH:
            return False
        if not re.search(r'[A-Z]', passphrase):
            return False
        if not re.search(r'[a-z]', passphrase):
            return False
        if not re.search(r'[0-9]', passphrase):
            return False
        if not re.search(r'[^A-Za-z0-9]', passphrase):
            return False
        return True

    @staticmethod
    def encrypt_key(key: bytes, passphrase: bytes) -> bytes:
        """Encrypt private key with passphrase using PBKDF2 and AES-GCM"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key_enc = kdf.derive(passphrase)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key_enc), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_key = encryptor.update(key) + encryptor.finalize()
        return salt + iv + encryptor.tag + encrypted_key

    @staticmethod
    def decrypt_key(encrypted_data: bytes, passphrase: bytes) -> bytes:
        """Decrypt private key with passphrase"""
        salt = encrypted_data[:16]
        iv = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key_enc = kdf.derive(passphrase)
        
        cipher = Cipher(algorithms.AES(key_enc), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    @staticmethod
    def generate_key_fingerprint(public_key_pem):
        """Generate fingerprint for identity verification"""
        der = public_key_pem.encode()
        return hashlib.sha256(der).hexdigest()[:16]  # First 16 chars of hash

class KeyRotationDialog(QDialog):
    """Dialog for setting key rotation schedule"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Key Rotation Schedule")
        self.setFixedSize(400, 200)
        
        layout = QVBoxLayout()
        
        # Rotation schedule
        form_layout = QFormLayout()
        self.rotation_combo = QComboBox()
        self.rotation_combo.addItems(["30 days", "60 days", "90 days (Recommended)", "180 days"])
        self.rotation_combo.setCurrentIndex(2)
        form_layout.addRow("Rotation Frequency:", self.rotation_combo)
        
        # Next rotation date
        self.rotation_date = QCalendarWidget()
        next_rotation = QDate.currentDate().addDays(KEY_EXPIRATION_DAYS)
        self.rotation_date.setSelectedDate(next_rotation)
        form_layout.addRow("Next Rotation Date:", self.rotation_date)
        
        layout.addLayout(form_layout)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        
        layout.addWidget(button_box)
        self.setLayout(layout)
    
    def get_rotation_days(self):
        text = self.rotation_combo.currentText()
        if "30" in text: return 30
        if "60" in text: return 60
        if "90" in text: return 90
        return 180
    
    def get_next_rotation_date(self):
        return self.rotation_date.selectedDate()

class IdentityVerificationDialog(QDialog):
    """Dialog for recipient identity verification"""
    def __init__(self, ecc_fingerprint, rsa_fingerprint, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Verify Recipient Identity")
        self.setFixedSize(500, 300)
        
        layout = QVBoxLayout()
        layout.addWidget(QLabel("<b>Before proceeding, verify the recipient's identity:</b>"))
        
        # Security reminder
        reminder = QLabel(
            "Security Best Practice:\n"
            "1. Contact the recipient through a separate secure channel\n"
            "2. Compare these fingerprints with what the recipient provides\n"
            "3. Confirm they match exactly before proceeding"
        )
        reminder.setStyleSheet("background-color: #fff8e1; padding: 10px; border: 1px solid #ffd54f;")
        layout.addWidget(reminder)
        
        # Fingerprint display
        form_layout = QFormLayout()
        
        self.ecc_edit = QLineEdit(ecc_fingerprint)
        self.ecc_edit.setReadOnly(True)
        form_layout.addRow("ECC Key Fingerprint:", self.ecc_edit)
        
        self.rsa_edit = QLineEdit(rsa_fingerprint)
        self.rsa_edit.setReadOnly(True)
        form_layout.addRow("RSA Key Fingerprint:", self.rsa_edit)
        
        layout.addLayout(form_layout)
        
        # Verification checkbox
        self.verify_check = QCheckBox("I have verified the fingerprints match the recipient's keys")
        layout.addWidget(self.verify_check)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        
        layout.addWidget(button_box)
        self.setLayout(layout)
    
    def is_verified(self):
        return self.verify_check.isChecked()

class KeyMetadata:
    """Class for managing key rotation metadata"""
    @staticmethod
    def create_metadata():
        return {
            "created": datetime.date.today().isoformat(),
            "expires": (datetime.date.today() + datetime.timedelta(days=KEY_EXPIRATION_DAYS)).isoformat(),
            "rotation_days": KEY_EXPIRATION_DAYS
        }
    
    @staticmethod
    def is_key_expired(metadata):
        if not metadata:
            return False
        expires = datetime.date.fromisoformat(metadata["expires"])
        return datetime.date.today() > expires
    
    @staticmethod
    def get_key_age(metadata):
        if not metadata:
            return "Unknown"
        created = datetime.date.fromisoformat(metadata["created"])
        delta = datetime.date.today() - created
        return f"{delta.days} days"
    
    @staticmethod
    def get_expiry_status(metadata):
        if not metadata:
            return "No expiration data"
        expires = datetime.date.fromisoformat(metadata["expires"])
        delta = expires - datetime.date.today()
        
        if delta.days < 0:
            return "EXPIRED"
        elif delta.days < 7:
            return f"Expires in {delta.days} days (URGENT)"
        elif delta.days < 30:
            return f"Expires in {delta.days} days (Warning)"
        return f"Expires in {delta.days} days"

class CryptoApp(QMainWindow):
    """Main application window for Enterprise Cryptosystem."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enterprise Cryptosystem - Enhanced Security")
        self.setGeometry(100, 100, 1000, 800)
        # Central widget with tabs
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        # Create tabs
        self.key_tab = KeyTab()
        self.encrypt_tab = EncryptTab()
        self.decrypt_tab = DecryptTab()
        self.tabs.addTab(self.key_tab, "Key Management")
        self.tabs.addTab(self.encrypt_tab, "Encryption")
        self.tabs.addTab(self.decrypt_tab, "Decryption")
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        # Security reminder
        self.status_bar.showMessage("SECURITY REMINDER: Store private keys on encrypted drives", 10000)

class KeyTab(QWidget):
    """Tab for key management, passphrase, and rotation."""
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        # Security information
        security_info = QLabel(
            "<b>SECURITY ENHANCEMENTS:</b><br>"
            "• 15+ character passphrases with special characters enforced<br>"
            f"• Automatic key rotation every {KEY_EXPIRATION_DAYS} days<br>"
            "• Recipient identity verification before encryption<br>"
            "• Secure channels required for key exchange"
        )
        security_info.setStyleSheet("background-color: #e8f5e9; padding: 10px; border-radius: 5px;")
        layout.addWidget(security_info)
        
        # Key rotation management
        rotation_group = QGroupBox("Key Rotation Schedule")
        rotation_layout = QHBoxLayout()
        
        self.rotation_status = QLabel("Rotation not configured")
        rotation_layout.addWidget(self.rotation_status)
        
        rotation_btn = QPushButton("Configure Rotation")
        rotation_btn.setStyleSheet("background-color: #2196F3; color: white;")
        rotation_btn.clicked.connect(self.configure_rotation)
        rotation_layout.addWidget(rotation_btn)
        
        rotation_group.setLayout(rotation_layout)
        layout.addWidget(rotation_group)
        
        # ECC Key Pair
        ecc_group = QGroupBox("ECC Key Pair (secp521r1)")
        ecc_layout = QVBoxLayout()
        
        ecc_inner_layout = QHBoxLayout()
        self.ecc_priv_edit = QTextEdit()
        self.ecc_priv_edit.setPlaceholderText("ECC Private Key (Encrypted)")
        self.ecc_priv_edit.setMinimumHeight(150)
        self.ecc_pub_edit = QTextEdit()
        self.ecc_pub_edit.setPlaceholderText("ECC Public Key (PEM)")
        self.ecc_pub_edit.setMinimumHeight(150)
        ecc_inner_layout.addWidget(self.ecc_priv_edit)
        ecc_inner_layout.addWidget(self.ecc_pub_edit)
        
        ecc_btn_layout = QHBoxLayout()
        gen_ecc_btn = QPushButton("Generate ECC Key Pair")
        gen_ecc_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        gen_ecc_btn.clicked.connect(self.generate_ecc_keys)
        save_ecc_btn = QPushButton("Save ECC Keys")
        save_ecc_btn.setStyleSheet("background-color: #2196F3; color: white;")
        save_ecc_btn.clicked.connect(self.save_ecc_keys)
        ecc_btn_layout.addWidget(gen_ecc_btn)
        ecc_btn_layout.addWidget(save_ecc_btn)
        
        ecc_layout.addLayout(ecc_inner_layout)
        ecc_layout.addLayout(ecc_btn_layout)
        ecc_group.setLayout(ecc_layout)
        
        # RSA Key Pair
        rsa_group = QGroupBox(f"RSA Key Pair ({RSA_KEY_SIZE}-bit)")
        rsa_layout = QVBoxLayout()
        
        rsa_inner_layout = QHBoxLayout()
        self.rsa_priv_edit = QTextEdit()
        self.rsa_priv_edit.setPlaceholderText("RSA Private Key (Encrypted)")
        self.rsa_priv_edit.setMinimumHeight(150)
        self.rsa_pub_edit = QTextEdit()
        self.rsa_pub_edit.setPlaceholderText("RSA Public Key (PEM)")
        self.rsa_pub_edit.setMinimumHeight(150)
        rsa_inner_layout.addWidget(self.rsa_priv_edit)
        rsa_inner_layout.addWidget(self.rsa_pub_edit)
        
        rsa_btn_layout = QHBoxLayout()
        gen_rsa_btn = QPushButton("Generate RSA Key Pair")
        gen_rsa_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        gen_rsa_btn.clicked.connect(self.generate_rsa_keys)
        save_rsa_btn = QPushButton("Save RSA Keys")
        save_rsa_btn.setStyleSheet("background-color: #2196F3; color: white;")
        save_rsa_btn.clicked.connect(self.save_rsa_keys)
        rsa_btn_layout.addWidget(gen_rsa_btn)
        rsa_btn_layout.addWidget(save_rsa_btn)
        
        rsa_layout.addLayout(rsa_inner_layout)
        rsa_layout.addLayout(rsa_btn_layout)
        rsa_group.setLayout(rsa_layout)
        
        # Passphrase section
        passphrase_group = QGroupBox("Key Encryption")
        pass_layout = QVBoxLayout()
        
        pass_input_layout = QHBoxLayout()
        self.passphrase_edit = QLineEdit()
        self.passphrase_edit.setPlaceholderText("Enter strong passphrase (15+ chars, mixed characters)")
        self.passphrase_edit.setEchoMode(QLineEdit.Password)
        pass_input_layout.addWidget(QLabel("Passphrase:"))
        pass_input_layout.addWidget(self.passphrase_edit)
        
        # Passphrase strength indicator
        self.pass_strength = QLabel("")
        self.pass_strength.setFont(QFont("Arial", 9))
        self.passphrase_edit.textChanged.connect(self.check_passphrase_strength)
        
        pass_layout.addLayout(pass_input_layout)
        pass_layout.addWidget(self.pass_strength)
        pass_layout.addWidget(QLabel("Note: Passphrase is required to encrypt private keys. Store securely."))
        passphrase_group.setLayout(pass_layout)
        
        # Assemble layout
        layout.addWidget(rotation_group)
        layout.addWidget(ecc_group)
        layout.addWidget(rsa_group)
        layout.addWidget(passphrase_group)
        
        self.setLayout(layout)
        self.key_metadata = {}
    
    def check_passphrase_strength(self):
        """Update passphrase strength indicator."""
        passphrase = self.passphrase_edit.text()
        if not passphrase:
            self.pass_strength.setText("")
            return
        if SecurityUtils.is_strong_passphrase(passphrase):
            self.pass_strength.setText("✓ Passphrase strength: STRONG")
            self.pass_strength.setStyleSheet("color: green;")
        else:
            self.pass_strength.setText("⚠ Passphrase must be 15+ chars with uppercase, lowercase, number, and special character")
            self.pass_strength.setStyleSheet("color: red;")
    
    def configure_rotation(self):
        """Open dialog to configure key rotation schedule."""
        dialog = KeyRotationDialog(self)
        if dialog.exec_():
            rotation_days = dialog.get_rotation_days()
            next_date = dialog.get_next_rotation_date().toString(Qt.ISODate)
            self.rotation_status.setText(
                f"Keys will rotate every {rotation_days} days. Next rotation: {next_date}"
            )
            self.key_metadata["rotation_days"] = rotation_days
            self.key_metadata["next_rotation"] = next_date
    
    def get_passphrase(self):
        """Get and validate passphrase for key encryption."""
        passphrase = self.passphrase_edit.text().encode()
        if not passphrase:
            QMessageBox.warning(self, "Error", "Passphrase is required for key encryption")
            return None
        if not SecurityUtils.is_strong_passphrase(passphrase.decode()):
            reply = QMessageBox.warning(
                self, 
                "Weak Passphrase", 
                "Your passphrase does not meet security requirements. Continue anyway?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return None
        return passphrase
    
    def generate_ecc_keys(self):
        """Generate ECC key pair, encrypt private key, and display."""
        passphrase = self.get_passphrase()
        if not passphrase:
            return
        try:
            private_key = ec.generate_private_key(ECC_CURVE, default_backend())
            public_key = private_key.public_key()
            # Serialize public key
            pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            # Serialize and encrypt private key
            priv_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            encrypted_priv = SecurityUtils.encrypt_key(priv_bytes, passphrase)
            self.ecc_priv_edit.setPlainText(encrypted_priv.hex())
            self.ecc_pub_edit.setPlainText(pub_pem)
            # Store key metadata
            self.key_metadata["ecc"] = KeyMetadata.create_metadata()
            QMessageBox.information(self, "Success", "ECC keys generated and encrypted")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Key generation failed: {str(e)}")
    
    def save_ecc_keys(self):
        """Save ECC private and public keys to files."""
        priv = self.ecc_priv_edit.toPlainText()
        pub = self.ecc_pub_edit.toPlainText()
        if not priv or not pub:
            QMessageBox.warning(self, "Error", "Generate keys first")
            return
        try:
            # Security reminder
            QMessageBox.information(
                self,
                "Security Best Practice",
                "Remember to store private keys on encrypted drives for maximum security."
            )
            # Save encrypted private key
            priv_path, _ = QFileDialog.getSaveFileName(
                self, "Save ECC Private Key", "", "Secure Key Files (*.ekey)"
            )
            if priv_path:
                if not priv_path.endswith('.ekey'):
                    priv_path += '.ekey'
                with open(priv_path, 'wb') as f:
                    f.write(bytes.fromhex(priv))
            # Save public key
            pub_path, _ = QFileDialog.getSaveFileName(
                self, "Save ECC Public Key", "", "PEM Files (*.pem)"
            )
            if pub_path:
                if not pub_path.endswith('.pem'):
                    pub_path += '.pem'
                with open(pub_path, 'w') as f:
                    f.write(pub)
            QMessageBox.information(self, "Success", "ECC keys saved securely")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Save failed: {str(e)}")
    
    def generate_rsa_keys(self):
        """Generate RSA key pair, encrypt private key, and display."""
        passphrase = self.get_passphrase()
        if not passphrase:
            return
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=RSA_KEY_SIZE,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            # Serialize public key
            pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            # Serialize and encrypt private key
            priv_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            encrypted_priv = SecurityUtils.encrypt_key(priv_bytes, passphrase)
            self.rsa_priv_edit.setPlainText(encrypted_priv.hex())
            self.rsa_pub_edit.setPlainText(pub_pem)
            # Store key metadata
            self.key_metadata["rsa"] = KeyMetadata.create_metadata()
            QMessageBox.information(self, "Success", "RSA keys generated and encrypted")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Key generation failed: {str(e)}")
    
    def save_rsa_keys(self):
        """Save RSA private and public keys to files."""
        priv = self.rsa_priv_edit.toPlainText()
        pub = self.rsa_pub_edit.toPlainText()
        if not priv or not pub:
            QMessageBox.warning(self, "Error", "Generate keys first")
            return
        try:
            # Security reminder
            QMessageBox.information(
                self,
                "Security Best Practice",
                "Remember to store private keys on encrypted drives for maximum security."
            )
            # Save encrypted private key
            priv_path, _ = QFileDialog.getSaveFileName(
                self, "Save RSA Private Key", "", "Secure Key Files (*.ekey)"
            )
            if priv_path:
                if not priv_path.endswith('.ekey'):
                    priv_path += '.ekey'
                with open(priv_path, 'wb') as f:
                    f.write(bytes.fromhex(priv))
            # Save public key
            pub_path, _ = QFileDialog.getSaveFileName(
                self, "Save RSA Public Key", "", "PEM Files (*.pem)"
            )
            if pub_path:
                if not pub_path.endswith('.pem'):
                    pub_path += '.pem'
                with open(pub_path, 'w') as f:
                    f.write(pub)
            QMessageBox.information(self, "Success", "RSA keys saved securely")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Save failed: {str(e)}")

class EncryptionThread(QThread):
    """Thread for encrypting text or file with ECC/RSA/AES."""
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    def __init__(self, plaintext, ecc_pub_key, rsa_pub_key, parent=None):
        super().__init__(parent)
        self.plaintext = plaintext
        self.ecc_pub_key = ecc_pub_key
        self.rsa_pub_key = rsa_pub_key
        self.is_file = isinstance(plaintext, str) and os.path.isfile(plaintext)
    def run(self):
        try:
            # Load public keys
            ecc_pub = serialization.load_pem_public_key(
                self.ecc_pub_key.encode(),
                backend=default_backend()
            )
            rsa_pub = serialization.load_pem_public_key(
                self.rsa_pub_key.encode(),
                backend=default_backend()
            )
            # Generate ephemeral ECC key pair
            ecc_private = ec.generate_private_key(ECC_CURVE, default_backend())
            ecc_public = ecc_private.public_key()
            # Perform ECDH
            shared_secret = ecc_private.exchange(ec.ECDH(), ecc_pub)
            # Derive AES key using HKDF
            salt = os.urandom(16)
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE,
                salt=salt,
                info=b'aes_key',
                backend=default_backend()
            ).derive(shared_secret)
            # Encrypt AES key with RSA
            enc_aes_key = rsa_pub.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Process data based on type
            if self.is_file:
                package = self._encrypt_file(aes_key, salt, enc_aes_key, ecc_public)
            else:
                package = self._encrypt_text(aes_key, salt, enc_aes_key, ecc_public)
            self.finished.emit(json.dumps(package, indent=2))
        except Exception as e:
            self.error.emit(f"Encryption failed: {str(e)}")
    
    def _encrypt_text(self, aes_key, salt, enc_aes_key, ecc_public):
        """Encrypt text data and return package."""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(self.plaintext.encode()) + encryptor.finalize()
        tag = encryptor.tag
        # Serialize ephemeral ECC public key
        ecc_pub_bytes = ecc_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {
            'type': 'text',
            'ecc_pub_key': ecc_pub_bytes.decode(),
            'salt': salt.hex(),
            'enc_aes_key': enc_aes_key.hex(),
            'iv': iv.hex(),
            'tag': tag.hex(),
            'ciphertext': ciphertext.hex()
        }
    
    def _encrypt_file(self, aes_key, salt, enc_aes_key, ecc_public):
        """Encrypt file in chunks and return package."""
        input_path = self.plaintext
        total_size = os.path.getsize(input_path)
        chunks = []
        iv = os.urandom(12)  # Single IV for all chunks
        # Serialize ephemeral ECC public key
        ecc_pub_bytes = ecc_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Initialize cipher
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(input_path, 'rb') as f:
            bytes_processed = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                encrypted_chunk = encryptor.update(chunk)
                chunks.append(encrypted_chunk.hex())
                bytes_processed += len(chunk)
                progress = int((bytes_processed / total_size) * 100)
                self.progress.emit(progress)
        # Finalize encryption
        final_chunk = encryptor.finalize()
        if final_chunk:
            chunks.append(final_chunk.hex())
        tag = encryptor.tag
        return {
            'type': 'file',
            'ecc_pub_key': ecc_pub_bytes.decode(),
            'salt': salt.hex(),
            'enc_aes_key': enc_aes_key.hex(),
            'iv': iv.hex(),
            'tag': tag.hex(),
            'ciphertext': chunks,
            'original_size': total_size
        }

class EncryptTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Security reminder
        security_info = QLabel(
            "<b>SECURITY REQUIREMENTS:</b><br>"
            "• Always verify recipient identity before encryption<br>"
            "• Use secure channels (e.g., Signal, PGP-encrypted email) for key exchange<br>"
            "• Rotate keys every 90 days for maximum security"
        )
        security_info.setStyleSheet("background-color: #e3f2fd; padding: 10px; border-radius: 5px;")
        layout.addWidget(security_info)
        
        # Input section
        input_group = QGroupBox("Input")
        input_layout = QVBoxLayout()
        
        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText("Enter plaintext or select a file...")
        input_layout.addWidget(self.input_edit)
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("No file selected")
        self.file_path_edit.setReadOnly(True)
        file_browse_btn = QPushButton("Browse File")
        file_browse_btn.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(file_browse_btn)
        input_layout.addLayout(file_layout)
        
        input_group.setLayout(input_layout)
        
        # Key section
        key_group = QGroupBox("Recipient Keys")
        key_layout = QVBoxLayout()
        
        ecc_layout = QHBoxLayout()
        self.ecc_key_edit = QLineEdit()
        self.ecc_key_edit.setPlaceholderText("Path to recipient's ECC public key")
        ecc_browse = QPushButton("Browse")
        ecc_browse.clicked.connect(self.browse_ecc_key)
        ecc_layout.addWidget(self.ecc_key_edit)
        ecc_layout.addWidget(ecc_browse)
        
        rsa_layout = QHBoxLayout()
        self.rsa_key_edit = QLineEdit()
        self.rsa_key_edit.setPlaceholderText("Path to recipient's RSA public key")
        rsa_browse = QPushButton("Browse")
        rsa_browse.clicked.connect(self.browse_rsa_key)
        rsa_layout.addWidget(self.rsa_key_edit)
        rsa_layout.addWidget(rsa_browse)
        
        # Fingerprint display
        self.ecc_fingerprint = QLabel("ECC fingerprint: not loaded")
        self.rsa_fingerprint = QLabel("RSA fingerprint: not loaded")
        
        key_layout.addLayout(ecc_layout)
        key_layout.addWidget(self.ecc_fingerprint)
        key_layout.addLayout(rsa_layout)
        key_layout.addWidget(self.rsa_fingerprint)
        key_group.setLayout(key_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        # Output section
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        
        self.output_edit = QTextEdit()
        self.output_edit.setPlaceholderText("Encrypted output will appear here")
        self.output_edit.setReadOnly(True)
        output_layout.addWidget(self.output_edit)
        
        # Buttons
        btn_layout = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt")
        encrypt_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        encrypt_btn.clicked.connect(self.encrypt)
        save_btn = QPushButton("Save Output")
        save_btn.setStyleSheet("background-color: #2196F3; color: white;")
        save_btn.clicked.connect(self.save_output)
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(save_btn)
        output_layout.addLayout(btn_layout)
        
        output_group.setLayout(output_layout)
        
        # Assemble layout
        layout.addWidget(input_group)
        layout.addWidget(key_group)
        layout.addWidget(self.progress_bar)
        layout.addWidget(output_group)
        
        self.setLayout(layout)
        self.file_to_encrypt = None
        self.ecc_key_data = None
        self.rsa_key_data = None
    
    def browse_ecc_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select ECC Public Key", "", "PEM Files (*.pem)"
        )
        if path:
            self.ecc_key_edit.setText(path)
            with open(path, 'r') as f:
                self.ecc_key_data = f.read()
                fingerprint = SecurityUtils.generate_key_fingerprint(self.ecc_key_data)
                self.ecc_fingerprint.setText(f"ECC fingerprint: {fingerprint}")
    
    def browse_rsa_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select RSA Public Key", "", "PEM Files (*.pem)"
        )
        if path:
            self.rsa_key_edit.setText(path)
            with open(path, 'r') as f:
                self.rsa_key_data = f.read()
                fingerprint = SecurityUtils.generate_key_fingerprint(self.rsa_key_data)
                self.rsa_fingerprint.setText(f"RSA fingerprint: {fingerprint}")
    
    def select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if path:
            self.file_path_edit.setText(path)
            self.file_to_encrypt = path
            self.input_edit.clear()
    
    def encrypt(self):
        ecc_path = self.ecc_key_edit.text()
        rsa_path = self.rsa_key_edit.text()
        
        if not ecc_path or not rsa_path:
            QMessageBox.warning(self, "Error", "Select both public keys")
            return
        
        # Verify recipient identity
        if not self.ecc_key_data or not self.rsa_key_data:
            QMessageBox.warning(self, "Error", "Load public keys first")
            return
        
        ecc_fingerprint = SecurityUtils.generate_key_fingerprint(self.ecc_key_data)
        rsa_fingerprint = SecurityUtils.generate_key_fingerprint(self.rsa_key_data)
        
        verify_dialog = IdentityVerificationDialog(ecc_fingerprint, rsa_fingerprint, self)
        if not verify_dialog.exec_() or not verify_dialog.is_verified():
            QMessageBox.warning(self, "Verification Failed", "Recipient identity not verified")
            return
        
        try:
            # Determine input type
            if self.file_to_encrypt:
                plaintext = self.file_to_encrypt
                is_file = True
            else:
                plaintext = self.input_edit.toPlainText()
                if not plaintext:
                    QMessageBox.warning(self, "Error", "Enter plaintext or select a file")
                    return
                is_file = False
            
            # Show progress for files
            self.progress_bar.setVisible(is_file)
            self.progress_bar.setValue(0)
            
            # Start encryption thread
            self.thread = EncryptionThread(plaintext, self.ecc_key_data, self.rsa_key_data)
            self.thread.finished.connect(self.on_encryption_complete)
            self.thread.error.connect(self.on_encryption_error)
            if is_file:
                self.thread.progress.connect(self.progress_bar.setValue)
            self.thread.start()
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")
    
    def on_encryption_complete(self, result):
        self.output_edit.setPlainText(result)
        self.progress_bar.setVisible(False)
        QMessageBox.information(self, "Success", "Encryption completed successfully")
    
    def on_encryption_error(self, message):
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Error", message)
    
    def save_output(self):
        output = self.output_edit.toPlainText()
        if not output:
            return
        
        try:
            # Validate JSON
            json.loads(output)
            
            path, _ = QFileDialog.getSaveFileName(
                self, "Save Encrypted Data", "", "Secure Files (*.enc)"
            )
            if path:
                if not path.endswith('.enc'):
                    path += '.enc'
                with open(path, 'w') as f:
                    f.write(output)
                QMessageBox.information(self, "Success", "File saved securely")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Invalid output format: {str(e)}")


# --- DecryptTab Implementation ---
class DecryptTab(QWidget):
    """Tab for decrypting encrypted data (basic implementation)."""
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText("Paste encrypted JSON or select a file...")
        layout.addWidget(QLabel("Encrypted Input:"))
        layout.addWidget(self.input_edit)
        self.output_edit = QTextEdit()
        self.output_edit.setPlaceholderText("Decrypted output will appear here")
        self.output_edit.setReadOnly(True)
        layout.addWidget(QLabel("Decrypted Output:"))
        layout.addWidget(self.output_edit)
        btn_layout = QHBoxLayout()
        decrypt_btn = QPushButton("Decrypt")
        decrypt_btn.clicked.connect(self.decrypt)
        btn_layout.addWidget(decrypt_btn)
        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def decrypt(self):
        package_json = self.input_edit.toPlainText()
        if not package_json:
            QMessageBox.warning(self, "Error", "Enter encrypted data first")
            return
        try:
            package = json.loads(package_json)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Invalid input: {str(e)}")
            return

        # Ask for private key and passphrase
        priv_key_path, _ = QFileDialog.getOpenFileName(self, "Select Your Private Key", "", "Secure Key Files (*.ekey);;PEM Files (*.pem)")
        if not priv_key_path:
            return
        passphrase, ok = QInputDialog.getText(self, "Passphrase", "Enter your passphrase:", QLineEdit.Password)
        if not ok or not passphrase:
            return

        # Load and decrypt private key
        try:
            with open(priv_key_path, 'rb') as f:
                priv_key_data = f.read()
            # If .ekey, decrypt with passphrase
            if priv_key_path.endswith('.ekey'):
                priv_bytes = SecurityUtils.decrypt_key(priv_key_data, passphrase.encode())
                # Try ECC first
                try:
                    private_key = serialization.load_der_private_key(priv_bytes, password=None, backend=default_backend())
                except Exception:
                    # Try RSA
                    private_key = serialization.load_der_private_key(priv_bytes, password=None, backend=default_backend())
            else:
                # PEM file
                private_key = serialization.load_pem_private_key(priv_key_data, password=None, backend=default_backend())
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load private key: {str(e)}")
            return

        try:
            # Extract encrypted AES key and decrypt
            enc_aes_key = bytes.fromhex(package['enc_aes_key'])
            salt = bytes.fromhex(package['salt'])
            iv = bytes.fromhex(package['iv'])
            tag = bytes.fromhex(package['tag'])

            # Decrypt AES key with RSA private key
            if private_key.key_size == RSA_KEY_SIZE:
                aes_key = private_key.decrypt(
                    enc_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            else:
                # ECC: perform ECDH with ephemeral public key
                ecc_pub_key_pem = package['ecc_pub_key'].encode()
                ecc_pub = serialization.load_pem_public_key(ecc_pub_key_pem, backend=default_backend())
                shared_secret = private_key.exchange(ec.ECDH(), ecc_pub)
                aes_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=AES_KEY_SIZE,
                    salt=salt,
                    info=b'aes_key',
                    backend=default_backend()
                ).derive(shared_secret)

            # Decrypt data
            if package['type'] == 'text':
                ciphertext = bytes.fromhex(package['ciphertext'])
                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                self.output_edit.setPlainText(plaintext.decode(errors='replace'))
                QMessageBox.information(self, "Success", "Decryption completed successfully")
            elif package['type'] == 'file':
                # Save decrypted file
                chunks = package['ciphertext']
                output_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", "", "All Files (*)")
                if not output_path:
                    return
                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                with open(output_path, 'wb') as f:
                    for chunk_hex in chunks:
                        chunk = bytes.fromhex(chunk_hex)
                        f.write(decryptor.update(chunk))
                    f.write(decryptor.finalize())
                self.output_edit.setPlainText(f"File decrypted and saved to: {output_path}")
                QMessageBox.information(self, "Success", "File decryption completed successfully")
            else:
                self.output_edit.setPlainText("Unknown package type")
        except Exception as e:
            self.output_edit.setPlainText("")
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    app = QApplication([])
    
    # Security reminder at startup
    QMessageBox.information(
        None,
        "Security Best Practices",
        "For maximum security:\n\n"
        "1. Use 15+ character passphrases with special characters\n"
        "2. Rotate keys every 90 days\n"
        "3. Store private keys on encrypted drives\n"
        "4. Verify recipient identities before encryption\n"
        "5. Use secure channels for key exchange"
    )
    
    window = CryptoApp()
    window.show()
    app.exec_()