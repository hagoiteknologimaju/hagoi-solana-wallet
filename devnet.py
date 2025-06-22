from solana.rpc.api import Client
from solana.keypair import Keypair
from solana.publickey import PublicKey
from solana.system_program import TransferParams, transfer
from solana.transaction import Transaction
import base58
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
from tkinter import filedialog, messagebox
import customtkinter as ctk
import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import requests
from datetime import datetime
import json
import threading
import hashlib
import qrcode
from PIL import Image, ImageTk, ImageDraw
import io
from io import BytesIO
import logging
from typing import Optional, Dict, Any
import re
from mnemonic import Mnemonic
import hashlib
import hmac
import binascii


class WalletEncryption: 
    @staticmethod
    def generate_key_from_password(password: str, salt: bytes = None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    @staticmethod
    def encrypt_data(data: str, password: str, salt: bytes = None):
        key, salt = WalletEncryption.generate_key_from_password(password, salt)
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode())
        return encrypted_data, salt

    @staticmethod
    def decrypt_data(encrypted_data: bytes, password: str, salt: bytes):
        key, _ = WalletEncryption.generate_key_from_password(password, salt)
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode()


class SolanaWallet:
    def __init__(self, network="devnet"):
        # Initialize Solana client with the specified network
        self.network = network
        self.endpoint = (
            "https://api.devnet.solana.com"
            if network == "devnet"
            else "https://api.mainnet-beta.solana.com"
        )
        self.client = Client(self.endpoint)
        self.max_retries = 3
        self.current_wallet = None  # Tambahkan current_wallet di sini
        self._lock = threading.Lock()
        self._logger = logging.getLogger(__name__)
        self._wallet_data: Dict[str, Any] = {}
        self.mnemo = Mnemonic("english")  # Inisialisasi Mnemonic untuk bahasa Inggris

    def _retry_operation(self, operation_func, *args, **kwargs):
        """Helper method to retry operations with the Solana client"""
        last_error = None
        for attempt in range(self.max_retries):
            try:
                return operation_func(*args, **kwargs)
            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    # Wait a bit before retrying (exponential backoff)
                    time.sleep(0.5 * (2**attempt))
                    # Recreate client in case connection is stale
                    self.client = Client(self.endpoint)

        # If we get here, all retries failed
        raise RuntimeError(
            f"Error after {self.max_retries} attempts: {str(last_error)}"
        )

    def _safe_operation(self, operation):
        """Thread-safe wrapper untuk operasi wallet"""
        with self._lock:
            try:
                return operation()
            except Exception as e:
                self._logger.error(f"Error dalam operasi wallet: {str(e)}")
                raise

    def create_wallet(self):
        """Create a new Hagoi Wallet"""

        def _create():
            try:
                # Generate new keypair
                keypair = Keypair()

                # Create wallet data dictionary
                wallet_data = {
                    "private_key": base58.b58encode(keypair.secret_key).decode("ascii"),
                    "public_key": str(keypair.public_key),
                }

                self._wallet_data = wallet_data
                return wallet_data

            except Exception as e:
                self._logger.error(f"Gagal membuat wallet: {str(e)}")
                raise

        return self._safe_operation(_create)

    def get_balance(self, public_key):
        """Get the balance of a wallet"""

        def _get_balance():
            try:
                # Convert string public key to PublicKey object
                pubkey = PublicKey(public_key)
                balance = self.client.get_balance(pubkey)
                # The response format is now a direct value
                return balance.value / 1e9  # Convert lamports to SOL
            except Exception as e:
                self._logger.error(f"Gagal mendapatkan saldo: {str(e)}")
                raise

        return self._safe_operation(_get_balance)

    def send_transaction(self, from_private_key, to_public_key, amount_sol):
        """Send SOL to another wallet with improved error handling and memory management"""

        def _send():
            try:
                # Convert amount to lamports
                amount_lamports = int(amount_sol * 1e9)

                # Validate inputs
                if amount_lamports <= 0:
                    raise ValueError("Amount must be greater than 0")

                # Convert keys
                from_keypair = Keypair.from_secret_key(
                    base58.b58decode(from_private_key)
                )
                to_pubkey = PublicKey(to_public_key)

                # Create and sign transaction
                transaction = Transaction()
                transaction.add(
                    transfer(
                        TransferParams(
                            from_pubkey=from_keypair.public_key,
                            to_pubkey=to_pubkey,
                            lamports=amount_lamports,
                        )
                    )
                )

                # Get recent blockhash using get_latest_blockhash
                blockhash_resp = self.client.get_latest_blockhash()
                if not blockhash_resp or not blockhash_resp.value:
                    raise RuntimeError("Failed to get latest blockhash")

                # Convert blockhash to string format
                transaction.recent_blockhash = str(blockhash_resp.value.blockhash)

                # Sign transaction
                transaction.sign(from_keypair)

                # Send transaction with proper error handling
                try:
                    result = self.client.send_transaction(transaction, from_keypair)
                    if not result or not result.value:
                        raise RuntimeError("Failed to get transaction signature")

                    # Convert signature to string
                    signature = str(result.value)

                    # Clean up
                    del transaction
                    del from_keypair

                    return signature

                except Exception as e:
                    error_str = str(e)
                    # Handle specific error cases
                    if "insufficient lamports" in error_str.lower():
                        # Extract the numbers from the error message
                        numbers = re.findall(r"\d+", error_str)
                        if len(numbers) >= 2:
                            available = float(numbers[0]) / 1e9
                            needed = float(numbers[1]) / 1e9
                            fee = needed - amount_sol
                            error_msg = f"\nInsufficient balance. Use 'Max' button."
                            raise RuntimeError(error_msg)
                        else:
                            raise RuntimeError(
                                "Insufficient balance to complete the transaction"
                            )
                    elif "custom program error: 0x1" in error_str:
                        raise RuntimeError(
                            "Transaction failed: Insufficient balance (including fee)"
                        )
                    else:
                        self._logger.error(f"Error sending transaction: {error_str}")
                        raise RuntimeError(f"Transaction failed: {error_str}")

            except Exception as e:
                self._logger.error(f"Failed to send transaction: {str(e)}")
                raise

        return self._safe_operation(_send)

    def __del__(self):
        """Cleanup resources when object is destroyed"""
        try:
            if hasattr(self, "_wallet_data"):
                del self._wallet_data
            if hasattr(self, "client"):
                del self.client
        except Exception as e:
            self._logger.error(f"Error saat cleanup: {str(e)}")

    def request_airdrop(self, public_key_str, amount_sol=1):
        """Request airdrop with improved validation and error handling"""

        def _request():
            try:
                # Validate amount
                if amount_sol <= 0 or amount_sol > 2:
                    raise ValueError("Airdrop amount must be between 0 and 2 SOL")

                # Convert to lamports
                amount_lamports = int(amount_sol * 1e9)

                # Convert public key
                public_key = PublicKey(public_key_str)

                # Request airdrop
                signature = self.client.request_airdrop(public_key, amount_lamports)

                # Wait for confirmation
                self.client.confirm_transaction(signature)

                return signature

            except Exception as e:
                self._logger.error(f"Gagal melakukan airdrop: {str(e)}")
                raise

        return self._safe_operation(_request)

    def validate_wallet(self, wallet_data: Dict[str, Any]) -> bool:
        """Validate wallet data structure and content"""
        try:
            required_fields = ["private_key", "public_key"]

            # Check required fields
            if not all(field in wallet_data for field in required_fields):
                return False

            # Validate public key format
            try:
                PublicKey(wallet_data["public_key"])
            except:
                return False

            # Validate private key format
            try:
                Keypair.from_secret_key(base58.b58decode(wallet_data["private_key"]))
            except:
                return False

            return True

        except Exception as e:
            self._logger.error(f"Error validasi wallet: {str(e)}")
            return False

    def generate_mnemonic(self) -> str:
        """Generate a new mnemonic phrase"""
        try:
            return self.mnemo.generate(strength=256)  # 24 kata untuk keamanan maksimum
        except Exception as e:
            self._logger.error(f"Error generating mnemonic: {str(e)}")
            raise

    def validate_mnemonic(self, mnemonic: str) -> bool:
        """Validate a mnemonic phrase"""
        try:
            return self.mnemo.check(mnemonic)
        except Exception as e:
            self._logger.error(f"Error validating mnemonic: {str(e)}")
            return False

    def mnemonic_to_seed(self, mnemonic: str, passphrase: str = "") -> bytes:
        """Convert mnemonic phrase to seed"""
        try:
            return self.mnemo.to_seed(mnemonic, passphrase)
        except Exception as e:
            self._logger.error(f"Error converting mnemonic to seed: {str(e)}")
            raise

    def seed_to_keypair(self, seed: bytes) -> Keypair:
        """Convert seed to Solana keypair"""
        try:
            # Gunakan seed untuk menghasilkan keypair
            keypair = Keypair.from_seed(seed[:32])  # Ambil 32 byte pertama dari seed
            return keypair
        except Exception as e:
            self._logger.error(f"Error converting seed to keypair: {str(e)}")
            raise

    def import_from_mnemonic(self, mnemonic: str, passphrase: str = "") -> Dict[str, str]:
        """Import wallet from mnemonic phrase"""
        try:
            # Validasi mnemonic
            if not self.validate_mnemonic(mnemonic):
                raise ValueError("Invalid mnemonic phrase")

            # Konversi mnemonic ke seed
            seed = self.mnemonic_to_seed(mnemonic, passphrase)

            # Konversi seed ke keypair
            keypair = self.seed_to_keypair(seed)

            # Buat wallet data
            wallet_data = {
                "private_key": base58.b58encode(keypair.secret_key).decode("ascii"),
                "public_key": str(keypair.public_key),
                "mnemonic": mnemonic,  # Simpan mnemonic untuk referensi
            }

            return wallet_data

        except Exception as e:
            self._logger.error(f"Error importing from mnemonic: {str(e)}")
            raise


import customtkinter as ctk
import tkinter as tk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import requests
from datetime import datetime
import json
import threading
import time


class SolanaWalletGUI:
    # Color constants for minimalistic theme
    COLORS = {
        "primary": "#854c94",  # Warna ungu dari ikon
        "background": "#121212",  # Dark background
        "surface": "#1E1E1E",  # Card/surface color
        "text": "#FFFFFF",
        "text_secondary": "#A0A0A0",
        "success": "#854c94",  # Menggunakan warna ungu untuk success
        "error": "#FF3D00",
        "hover": "#a366b8",  # Warna hover yang sedikit lebih terang dari primary
    }

    def update_button_icons(self):
        """Update buttons with icons"""
        try:
            # Check if icons are loaded yet
            if not self.icons:
                print("Icons not yet loaded, skipping button update.")
                return

            # Update buttons with icons
            self.create_wallet_btn.configure(
                image=self.icons.get("plus"),
                compound="left",
                text=" Create Wallet",
                font=ctk.CTkFont(size=13, weight="bold"),
            )

            self.import_wallet_btn.configure(
                image=self.icons.get("wallet"),
                compound="left",
                text=" Import",
                font=ctk.CTkFont(size=13, weight="bold"),
            )

            self.transfer_btn.configure(
                image=self.icons.get("send"),
                compound="left",
                text=" Transfer",
                font=ctk.CTkFont(size=13, weight="bold"),
            )

            self.chart_btn.configure(
                image=self.icons.get("chart"),
                compound="left",
                text=" Price Chart",
                font=ctk.CTkFont(size=13, weight="bold"),
            )

            self.qr_btn.configure(
                image=self.icons.get("solana"),
                compound="left",
                text=" Receive SOL",
                font=ctk.CTkFont(size=13, weight="bold"),
            )

            # Update copy button dengan ikon saja
            self.copy_key_btn.configure(
                image=self.icons.get("copy"), text="", font=ctk.CTkFont(size=13)
            )
        except Exception as e:
            print(f"Error updating button icons: {str(e)}")

    def __init__(self):
        self.wallet = SolanaWallet(network="devnet")
        self.current_wallet = None
        self.session_start_time = datetime.now()
        self.session_timeout_minutes = 15
        self.last_activity_time = datetime.now()
        self.transaction_history = []
        self.default_wallet_path = os.path.join(
            os.path.expanduser("~"), ".solana_default_wallet.hagoi"
        )
        self.history_dir = os.path.abspath(
            os.path.join(os.path.expanduser("~"), ".solana_wallet_history")
        )
        self.is_closing = False
        self.is_logging_out = False
        self.price_thread = None
        self.balance_thread = None
        self.is_startup = True
        self.current_sol_price = None
        self._last_realtime_price_call = 0
        self._last_chart_price_call = 0
        self.last_chart_data = None
        self.last_chart_update = None
        self.last_balance = None

        # Create the main window
        self.window = ctk.CTk()
        self.window.title("Hagoi Wallet")
        self.window.resizable(False, False)
        self.window.geometry("380x680")

        # Set background color
        self.window.configure(fg_color=self.COLORS["background"])

        # Set title bar color for main window
        try:
            from ctypes import windll, byref, sizeof, c_int

            DWMWA_CAPTION_COLOR = 35
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            DWMWA_MICA_EFFECT = 1029

            # Set dark mode
            windll.dwmapi.DwmSetWindowAttribute(
                windll.user32.GetParent(self.window.winfo_id()),
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                byref(c_int(1)),
                sizeof(c_int),
            )

            # Set Mica effect
            windll.dwmapi.DwmSetWindowAttribute(
                windll.user32.GetParent(self.window.winfo_id()),
                DWMWA_MICA_EFFECT,
                byref(c_int(1)),
                sizeof(c_int),
            )

            # Set title bar color
            color = int(self.COLORS["background"].replace("#", ""), 16)
            windll.dwmapi.DwmSetWindowAttribute(
                windll.user32.GetParent(self.window.winfo_id()),
                DWMWA_CAPTION_COLOR,
                byref(c_int(color)),
                sizeof(c_int),
            )
        except Exception as e:
            print(f"Error setting window attributes: {str(e)}")

        # Initialize icons dict early
        self.icons = {}

        # Create the history directory if it doesn't exist
        try:
            if not os.path.exists(self.history_dir):
                os.makedirs(self.history_dir)
                print(f"Created history directory at: {self.history_dir}")
        except Exception as e:
            print(f"Error creating history directory: {str(e)}")

        # Initialize price data for chart and USD calculation
        self.price_data = []
        self.time_data = []

        # Configure the appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        # Setup UI components
        self.setup_ui()

        # Do not update button icons immediately, wait for thread
        # self.update_button_icons()

        # Set up window close event handler
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Start check for default wallet at startup
        if self.is_startup and not self.is_logging_out and not self.is_closing:
            self.check_for_default_wallet()
            self.is_startup = False

        # Start icon loading thread after UI is setup
        print("Starting icon loading thread...")
        icon_load_thread = threading.Thread(
            target=self._load_and_apply_icons, daemon=True
        )
        icon_load_thread.start()

    def _load_and_apply_icons(self):
        """Load and resize icons in a separate thread, then apply to buttons."""
        try:
            icon_types = ["wallet", "send", "receive", "chart", "copy", "solana", "plus"]
            icon_size = (24, 24)  # Define standard icon size
            loaded_icons = {}

            for icon_type in icon_types:
                try:
                    icon_path = os.path.join("icons", f"{icon_type}.png")
                    if os.path.exists(icon_path):
                        # Load original image
                        original_image = Image.open(icon_path)
                        # Resize to desired size
                        resized_image = original_image.resize(
                            icon_size, Image.Resampling.LANCZOS
                        )
                        # Convert to CTkImage for HighDPI support
                        # Use the same image for light and dark mode for simplicity
                        loaded_icons[icon_type] = ctk.CTkImage(
                            light_image=resized_image,
                            dark_image=resized_image,
                            size=icon_size,  # Specify display size for CTkImage
                        )
                        print(f"Successfully loaded icon: {icon_type}")
                    else:
                        print(f"Warning: Icon {icon_type}.png not found at {icon_path}")
                except Exception as e:
                    print(f"Error loading icon {icon_type}: {str(e)}")

            # Assign loaded icons to instance variable (thread-safe enough for dict assignment)
            self.icons = loaded_icons
            print("Icon loading complete.")

            # Apply icons to buttons on the main thread
            if self.window and self.window.winfo_exists():
                self.window.after(0, self.update_button_icons)
                print("Scheduled button icon update on main thread.")
            else:
                print("Main window not available, cannot schedule icon update.")

        except Exception as e:
            print(f"Error in icon loading thread: {str(e)}")

    def setup_ui(self):
        # Main container
        self.main_container = ctk.CTkFrame(self.window, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=16, pady=16)

        # Header
        self.header_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.header_frame.pack(fill="x", pady=(0, 16))

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text="Solana Network",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=self.COLORS["text"],
        )
        self.title_label.pack(side="left", pady=8)

        # Status wallet
        self.wallet_status_label = ctk.CTkLabel(
            self.header_frame,
            text="No wallet loaded",
            font=ctk.CTkFont(size=12),
            text_color=self.COLORS["text_secondary"],
        )
        self.wallet_status_label.pack(side="right", pady=8)

        # Balance card
        self.balance_card = ctk.CTkFrame(
            self.main_container, fg_color=self.COLORS["surface"], corner_radius=12
        )
        self.balance_card.pack(fill="x", pady=8)

        self.balance_label = ctk.CTkLabel(
            self.balance_card,
            text="0 SOL",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=self.COLORS["text"],
        )
        self.balance_label.pack(pady=(16, 4))

        # USD balance
        self.usd_balance_label = ctk.CTkLabel(
            self.balance_card,
            text="≈ $0.00 USD",
            font=ctk.CTkFont(size=14),
            text_color=self.COLORS["text_secondary"],
        )
        self.usd_balance_label.pack(pady=(0, 16))

        # Public key card
        self.public_key_card = ctk.CTkFrame(
            self.main_container, fg_color=self.COLORS["surface"], corner_radius=12
        )
        self.public_key_card.pack(fill="x", pady=8)

        # Frame untuk public key dan tombol copy
        key_frame = ctk.CTkFrame(self.public_key_card, fg_color="transparent")
        key_frame.pack(fill="x", padx=12, pady=12)

        self.public_key_label = ctk.CTkLabel(
            key_frame,
            text="Public Key: None",
            wraplength=260,
            font=ctk.CTkFont(size=12),
            text_color=self.COLORS["text"],
        )
        self.public_key_label.pack(side="left", expand=True, fill="x")

        # Copy button yang lebih besar
        self.copy_key_btn = ctk.CTkButton(
            key_frame,
            text="",
            command=self.copy_public_key_to_clipboard,
            width=45,
            height=45,
            corner_radius=8,
            fg_color="transparent",  # Ubah menjadi transparan
            border_color=self.COLORS["primary"],  # Tambahkan border
            border_width=2,  # Atur lebar border
            hover_color=self.COLORS["hover"],
            text_color="#000000",  # Warna teks tidak terlihat karena tidak ada teks
        )
        self.copy_key_btn.pack(side="right", padx=(8, 0))

        # Action buttons
        self.actions_grid = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.actions_grid.pack(fill="x", pady=16)

        # Create New Wallet Button
        self.create_wallet_btn = ctk.CTkButton(
            self.actions_grid,
            text="Create New",
            command=self.create_new_wallet,
            width=150,
            height=40,
            corner_radius=8,
            fg_color="transparent",  # Ubah menjadi transparan
            border_color=self.COLORS["primary"],  # Tambahkan border
            border_width=2,  # Atur lebar border
            hover_color="#a366b8",  # Warna hover yang lebih terang
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#FFFFFF",  # Warna teks putih
        )
        self.create_wallet_btn.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")

        # Import Wallet Button
        self.import_wallet_btn = ctk.CTkButton(
            self.actions_grid,
            text="Import",
            command=self.import_wallet,
            width=150,
            height=40,
            corner_radius=8,
            fg_color="transparent",  # Ubah menjadi transparan
            border_color=self.COLORS["primary"],  # Tambahkan border
            border_width=2,  # Atur lebar border
            hover_color="#a366b8",  # Warna hover yang lebih terang
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#FFFFFF",  # Warna teks putih
        )
        self.import_wallet_btn.grid(row=0, column=1, padx=8, pady=8, sticky="nsew")

        # Transfer Button
        self.transfer_btn = ctk.CTkButton(
            self.actions_grid,
            text="Transfer",
            command=self.open_transfer_window,
            width=150,
            height=40,
            corner_radius=8,
            fg_color="transparent",  # Ubah menjadi transparan
            border_color=self.COLORS["primary"],  # Tambahkan border
            border_width=2,  # Atur lebar border
            hover_color="#a366b8",  # Warna hover yang lebih terang
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#FFFFFF",  # Warna teks putih
        )
        self.transfer_btn.grid(row=1, column=0, padx=8, pady=8, sticky="nsew")

        # Price Chart Button
        self.chart_btn = ctk.CTkButton(
            self.actions_grid,
            text="Price Chart",
            command=self.open_chart_window,
            width=150,
            height=40,
            corner_radius=8,
            fg_color="transparent",  # Ubah menjadi transparan
            border_color=self.COLORS["primary"],  # Tambahkan border
            border_width=2,  # Atur lebar border
            hover_color="#a366b8",  # Warna hover yang lebih terang
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#FFFFFF",  # Warna teks putih
        )
        self.chart_btn.grid(row=1, column=1, padx=8, pady=8, sticky="nsew")

        # Add QR code button to actions grid
        self.qr_btn = ctk.CTkButton(
            self.actions_grid,
            text="Receive SOL",
            command=self.show_receive_dialog,
            width=150,
            height=40,
            corner_radius=8,
            fg_color="transparent",  # Ubah menjadi transparan
            border_color=self.COLORS["primary"],  # Tambahkan border
            border_width=2,  # Atur lebar border
            hover_color="#a366b8",  # Warna hover yang lebih terang
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#FFFFFF",  # Warna teks putih
        )
        self.qr_btn.grid(row=2, column=0, columnspan=2, padx=8, pady=8, sticky="nsew")

        # Configure grid
        self.actions_grid.grid_columnconfigure(0, weight=1)
        self.actions_grid.grid_columnconfigure(1, weight=1)

        # Status label
        self.status_label = ctk.CTkLabel(
            self.main_container,
            text="",
            text_color=self.COLORS["success"],
            wraplength=340,
            font=ctk.CTkFont(size=12),
        )
        self.status_label.pack(pady=8)

        # Transaction History
        self.history_frame = ctk.CTkFrame(
            self.main_container, fg_color=self.COLORS["surface"], corner_radius=12
        )
        self.history_frame.pack(fill="both", expand=True, pady=8)

        # History scrollable frame
        self.history_scrollable_frame = ctk.CTkScrollableFrame(
            self.history_frame,
            label_text="Transaction History",
            label_font=ctk.CTkFont(size=14, weight="bold"),
            label_text_color=self.COLORS["text"],
            fg_color="transparent",
        )
        self.history_scrollable_frame.pack(fill="both", expand=True, padx=8, pady=8)

        # Initialize history display
        self._refresh_history_display()

    def _get_history_file_path(self, public_key):
        """Mendapatkan path file history untuk public key tertentu"""
        try:
            # Gunakan hash dari public key sebagai nama file untuk keamanan
            history_hash = hashlib.sha256(public_key.encode()).hexdigest()
            file_path = os.path.join(self.history_dir, f"{history_hash}.json")
            print(f"Generated history file path: {file_path}")
            return file_path
        except Exception as e:
            print(f"Error generating history file path: {str(e)}")
            return None

    def _load_transaction_history(self, public_key):
        """Memuat riwayat transaksi dari file untuk public key tertentu"""
        try:
            history_file = self._get_history_file_path(public_key)
            if not history_file:
                print("Failed to get history file path")
                return []

            print(f"Attempting to load history from: {history_file}")

            if os.path.exists(history_file):
                # Baca file dengan mode binary untuk menghindari masalah encoding di Windows
                with open(history_file, "rb") as f:
                    content = f.read().decode("utf-8")
                    print(
                        f"Raw file content: {content[:200]}..."
                    )  # Print first 200 chars
                    data = json.loads(content)
                    print(f"Successfully loaded history file. Data type: {type(data)}")

                    # Handle both old and new format
                    if isinstance(data, list):
                        print(f"Found old format data with {len(data)} transactions")
                        return data
                    elif isinstance(data, dict) and "transactions" in data:
                        print(
                            f"Found new format data with {len(data['transactions'])} transactions"
                        )
                        return data["transactions"]
                    print("Unknown data format in history file")
                    return []
            else:
                print(f"History file does not exist: {history_file}")
                return []
        except Exception as e:
            print(f"Error loading transaction history: {str(e)}")
            print(f"History file path: {history_file}")
            return []

    def _save_transaction_history(self, public_key, history):
        """Menyimpan riwayat transaksi ke file untuk public key tertentu"""
        try:
            history_file = self._get_history_file_path(public_key)
            if not history_file:
                print("Failed to get history file path")
                return

            # Pastikan direktori history ada
            os.makedirs(os.path.dirname(history_file), exist_ok=True)

            # Simpan history dengan format yang lebih terstruktur
            history_data = {
                "public_key": public_key,
                "transactions": history,
                "last_updated": datetime.now().isoformat(),
            }

            # Tulis ke file dengan mode binary untuk menghindari masalah encoding di Windows
            with open(history_file, "wb") as f:
                f.write(json.dumps(history_data, indent=2).encode("utf-8"))

            print(f"Transaction history saved successfully to: {history_file}")
            print(f"Number of transactions saved: {len(history)}")
        except Exception as e:
            print(f"Error saving transaction history: {str(e)}")
            print(f"History file path: {history_file}")
            print(f"History data: {history}")

    def _add_to_history(self, signature, amount, recipient):
        """Add transaction to history and save to file"""
        if not self.current_wallet:
            return

        # Persingkat signature agar tidak terlalu panjang
        short_sig = (
            f"{signature[:6]}...{signature[-6:]}" if len(signature) > 12 else signature
        )
        entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | To: {recipient[:8]}... | Amount: {amount} SOL | Sig: {short_sig}"

        # Tambahkan ke list history
        self.transaction_history.append(entry)

        # Simpan ke file
        self._save_transaction_history(
            self.current_wallet["public_key"], self.transaction_history
        )

        # Update tampilan
        self._refresh_history_display()

    def check_for_default_wallet(self):
        """Check if a default wallet file exists, and load it if possible"""
        if self.is_closing or self.is_logging_out or not self.is_startup:
            return

        if os.path.exists(self.default_wallet_path):
            try:
                password_result = self.show_password_dialog(action="import")
                if password_result["cancelled"] or not password_result["password"]:
                    # Jika user cancel atau tidak memasukkan password, tutup aplikasi
                    self.window.destroy()
                    os._exit(0)
                    return

                wallet_data = self.load_wallet_from_encrypted_file(
                    self.default_wallet_path, password_result["password"]
                )

                if isinstance(wallet_data, str):  # Error message
                    self.status_label.configure(text=wallet_data, text_color="red")
                    # Jika gagal load wallet, tutup aplikasi
                    self.window.destroy()
                    os._exit(0)
                    return

                self.current_wallet = wallet_data
                self.public_key_label.configure(
                    text=f"Public Key: {self.current_wallet['public_key']}"
                )

                # Load transaction history untuk wallet ini
                self.transaction_history = self._load_transaction_history(
                    self.current_wallet["public_key"]
                )

                self.update_balance()
                self.update_wallet_status()
                self._refresh_history_display()
                self.status_label.configure(text="", text_color="green")
                self.window.after(3000, self._clear_status_after_delay)
            except Exception as e:
                self.status_label.configure(
                    text=f"Error loading wallet: {str(e)}", text_color="red"
                )
                # Jika terjadi error, tutup aplikasi
                self.window.destroy()
                os._exit(0)

    def update_price_periodically(self):
        """Update price data in the background and schedule UI updates on the main thread"""
        while not self.is_closing and not self.is_logging_out:
            try:
                current_price = self.get_sol_price()

                if self.is_closing or self.is_logging_out:
                    break

                # Check if the chart window and its price_label exist before updating
                if hasattr(self, "price_label") and self.price_label.winfo_exists():
                    if current_price is not None:
                        # Schedule UI update on the main thread
                        self.window.after(
                            0, lambda p=current_price: self._safe_update_price_chart(p)
                        )
                    else:
                        # Update price label directly on the main thread if price is unavailable
                        self.window.after(
                            0,
                            lambda: self.price_label.configure(
                                text="SOL Price: Unavailable"
                            ),
                        )

                # Note: The main window's USD balance is updated within _safe_update_price_chart
                # even if the chart window is closed, because self.current_sol_price is updated.

                # Wait 30 seconds before next update
                for _ in range(30):  # Check flag every second for 30 seconds
                    if self.is_closing or self.is_logging_out:
                        break
                    time.sleep(1)
            except Exception as e:
                print(f"Error in price update thread: {str(e)}")
                # If an error occurs, still wait before retrying to avoid spamming
                time.sleep(30)

    def create_new_wallet(self):
        self._update_activity_timestamp()
        
        # Tanya user apakah ingin menggunakan mnemonic
        dlg = ctk.CTkToplevel(self.window)
        dlg.title("Create New Wallet")
        dlg.minsize(360, 200)
        dlg.transient(self.window)
        dlg.grab_set()

        # Setup dialog theme
        self._setup_dialog_theme(dlg)

        # Main frame
        main_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_label = ctk.CTkLabel(
            main_frame,
            text="Choose wallet creation method:",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.COLORS["text"],
        )
        title_label.pack(pady=(0, 20))

        def create_with_mnemonic():
            dlg.destroy()
            self._create_wallet_with_mnemonic()

        def create_without_mnemonic():
            dlg.destroy()
            self._create_wallet_without_mnemonic()

        # Button untuk membuat wallet dengan mnemonic
        mnemonic_btn = ctk.CTkButton(
            main_frame,
            text="Create with Mnemonic",
            command=create_with_mnemonic,
            width=320,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["primary"],
            hover_color=self.COLORS["hover"],
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#000000",
        )
        mnemonic_btn.pack(pady=10)

        # Button untuk membuat wallet tanpa mnemonic
        normal_btn = ctk.CTkButton(
            main_frame,
            text="Create without Mnemonic",
            command=create_without_mnemonic,
            width=320,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["primary"],
            hover_color=self.COLORS["hover"],
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#000000",
        )
        normal_btn.pack(pady=10)

        # Center dialog
        dlg.update_idletasks()
        width = dlg.winfo_width()
        height = dlg.winfo_height()
        x = self.window.winfo_x() + (self.window.winfo_width() // 2) - (width // 2)
        y = self.window.winfo_y() + (self.window.winfo_height() // 2) - (height // 2)
        dlg.geometry(f"{width}x{height}+{x}+{y}")

        dlg.wait_window()

    def _create_wallet_with_mnemonic(self):
        """Create a new wallet with mnemonic phrase"""
        try:
            # Generate mnemonic
            mnemonic = self.wallet.generate_mnemonic()
            
            # Tampilkan dialog untuk menampilkan mnemonic
            dlg = ctk.CTkToplevel(self.window)
            dlg.title("Your Mnemonic Phrase")
            dlg.minsize(360, 400)
            dlg.transient(self.window)
            dlg.grab_set()

            # Setup dialog theme
            self._setup_dialog_theme(dlg)

            # Main frame
            main_frame = ctk.CTkFrame(dlg, fg_color="transparent")
            main_frame.pack(fill="both", expand=True, padx=20, pady=20)

            # Warning label
            warning_label = ctk.CTkLabel(
                main_frame,
                text="IMPORTANT: Write down these words in order and keep them safe!",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color=self.COLORS["error"],
                wraplength=320,
            )
            warning_label.pack(pady=(0, 20))

            # Mnemonic display
            mnemonic_frame = ctk.CTkFrame(
                main_frame,
                fg_color=self.COLORS["surface"],
                corner_radius=8,
            )
            mnemonic_frame.pack(fill="x", pady=10)

            mnemonic_label = ctk.CTkLabel(
                mnemonic_frame,
                text=mnemonic,
                font=ctk.CTkFont(size=14),
                text_color=self.COLORS["text"],
                wraplength=300,
            )
            mnemonic_label.pack(pady=15, padx=15)

            # Copy button
            def copy_mnemonic():
                self.window.clipboard_clear()
                self.window.clipboard_append(mnemonic)
                copy_btn.configure(text="Copied!")
                dlg.after(2000, lambda: copy_btn.configure(text="Copy to Clipboard"))

            copy_btn = ctk.CTkButton(
                main_frame,
                text="Copy to Clipboard",
                command=copy_mnemonic,
                width=320,
                height=40,
                corner_radius=8,
                fg_color=self.COLORS["primary"],
                hover_color=self.COLORS["hover"],
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#000000",
            )
            copy_btn.pack(pady=10)

            def on_continue():
                dlg.destroy()
                # Import wallet dari mnemonic yang baru dibuat
                wallet_data = self.wallet.import_from_mnemonic(mnemonic)
                
                self.current_wallet = wallet_data
                self.public_key_label.configure(text=f"Public Key: {wallet_data['public_key']}")

                # Load transaction history
                self.transaction_history = self._load_transaction_history(wallet_data['public_key'])

                self.update_balance()
                self.update_wallet_status()
                self._refresh_history_display()
                self.status_label.configure(text="New wallet created successfully!", text_color="green")

                # Ask user where to save the wallet file
                file_path = filedialog.asksaveasfilename(
                    title="Save Wallet As",
                    defaultextension=".hagoi",
                    filetypes=(("Encrypted Wallet Files", "*.hagoi"), ("All files", "*.*")),
                )
                if not file_path:
                    self.status_label.configure(text="Wallet created but not saved", text_color="orange")
                    return

                # Get password for encryption
                password_result = self.show_password_dialog(action="create")
                if password_result["cancelled"] or not password_result["password"]:
                    self.status_label.configure(text="Wallet created but not saved", text_color="orange")
                    return

                # Save wallet to encrypted file
                result = self.save_wallet_to_encrypted_file(
                    self.current_wallet, password_result["password"], file_path
                )
                if result is True:
                    self.status_label.configure(
                        text=f"Wallet created and saved to {os.path.basename(file_path)}",
                        text_color="green",
                    )
                else:
                    self.status_label.configure(
                        text=f"Wallet created but error saving to file: {result}",
                        text_color="red",
                    )

            # Continue button
            continue_btn = ctk.CTkButton(
                main_frame,
                text="I've Written Down My Mnemonic",
                command=on_continue,
                width=320,
                height=40,
                corner_radius=8,
                fg_color=self.COLORS["primary"],
                hover_color=self.COLORS["hover"],
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#000000",
            )
            continue_btn.pack(pady=10)

            # Center dialog
            dlg.update_idletasks()
            width = dlg.winfo_width()
            height = dlg.winfo_height()
            x = self.window.winfo_x() + (self.window.winfo_width() // 2) - (width // 2)
            y = self.window.winfo_y() + (self.window.winfo_height() // 2) - (height // 2)
            dlg.geometry(f"{width}x{height}+{x}+{y}")

            dlg.wait_window()

        except Exception as e:
            self.status_label.configure(
                text=f"Error creating wallet: {str(e)}", text_color="red"
            )

    def _create_wallet_without_mnemonic(self):
        """Create a new wallet without mnemonic phrase"""
        password_dialog_result = self.show_password_dialog(action="create")
        if password_dialog_result["cancelled"]:
            return

        password = password_dialog_result["password"]

        self.current_wallet = self.wallet.create_wallet()
        self.public_key_label.configure(text=f"Public Key: {self.current_wallet['public_key']}")
        self.update_balance()
        self.update_wallet_status()
        self.status_label.configure(text="New wallet created successfully!", text_color="green")

        # Ask user where to save the wallet file
        file_path = filedialog.asksaveasfilename(
            title="Save Wallet As",
            defaultextension=".hagoi",
            filetypes=(("Encrypted Wallet Files", "*.hagoi"), ("All files", "*.*")),
        )
        if not file_path:
            self.status_label.configure(text="Wallet created but not saved", text_color="orange")
            return

        # Save wallet to encrypted file
        result = self.save_wallet_to_encrypted_file(
            self.current_wallet, password, file_path
        )
        if result is True:
            self.status_label.configure(
                text=f"Wallet created and saved to {os.path.basename(file_path)}",
                text_color="green",
            )
        else:
            self.status_label.configure(
                text=f"Wallet created but error saving to file: {result}",
                text_color="red",
            )

    def save_wallet_to_encrypted_file(self, wallet_data, password, file_path):
        """Save wallet data to encrypted binary file (.wallet)"""
        try:
            # Validate wallet data before saving
            if (
                not wallet_data
                or "public_key" not in wallet_data
                or "private_key" not in wallet_data
            ):
                return "Invalid wallet data"

            # Validate keypair coherence
            try:
                keypair = Keypair.from_secret_key(
                    base58.b58decode(wallet_data["private_key"])
                )
                if str(keypair.public_key) != wallet_data["public_key"]:
                    return "Warning: Public key doesn't match the private key"
            except Exception as e:
                return f"Invalid private key: {str(e)}"

            # Prepare data: public_key (utf-8), private_key (utf-8), salt (random)
            salt = os.urandom(16)
            key, _ = WalletEncryption.generate_key_from_password(password, salt)
            f = Fernet(key)
            # Format: public_key|private_key (delimiter is |)
            data = f"{wallet_data['public_key']}|{wallet_data['private_key']}".encode(
                "utf-8"
            )
            encrypted_data = f.encrypt(data)
            # File format: [salt (16 bytes)] + [encrypted_data]
            with open(file_path, "wb") as file:
                file.write(salt)
                file.write(encrypted_data)
            # Verify the file was written successfully
            # Verify the file's contents by attempting to read and decrypt it
            try:
                with open(file_path, "rb") as file:
                    saved_salt = file.read(16)
                    saved_encrypted_data = file.read()
                saved_key, _ = WalletEncryption.generate_key_from_password(
                    password, saved_salt
                )
                saved_f = Fernet(saved_key)
                saved_f.decrypt(saved_encrypted_data)  # Attempt decryption
            except Exception as e:
                return f"File verification failed: {str(e)}"

            return True
        except Exception as e:
            return f"Error saving wallet: {str(e)}"

    def _setup_dialog_theme(self, dialog):
        """Helper function to setup dialog theme"""
        # Set background color
        dialog.configure(fg_color=self.COLORS["background"])
        dialog.attributes("-alpha", 0.98)

        # Set title bar color (Windows)
        try:
            from ctypes import windll, byref, sizeof, c_int

            DWMWA_CAPTION_COLOR = 35
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            DWMWA_MICA_EFFECT = 1029

            # Set dark mode
            windll.dwmapi.DwmSetWindowAttribute(
                windll.user32.GetParent(dialog.winfo_id()),
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                byref(c_int(1)),
                sizeof(c_int),
            )

            # Set Mica effect
            windll.dwmapi.DwmSetWindowAttribute(
                windll.user32.GetParent(dialog.winfo_id()),
                DWMWA_MICA_EFFECT,
                byref(c_int(1)),
                sizeof(c_int),
            )

            # Set title bar color
            color = int(self.COLORS["background"].replace("#", ""), 16)
            windll.dwmapi.DwmSetWindowAttribute(
                windll.user32.GetParent(dialog.winfo_id()),
                DWMWA_CAPTION_COLOR,
                byref(c_int(color)),
                sizeof(c_int),
            )
        except Exception as e:
            print(f"Error setting window attributes: {str(e)}")

    def import_wallet(self):
        """Show dialog to choose wallet import method"""
        self._update_activity_timestamp()

        # Create dialog for choosing import method
        dlg = ctk.CTkToplevel(self.window)
        dlg.title("Import Wallet")
        dlg.minsize(360, 280)
        dlg.transient(self.window)
        dlg.grab_set()

        # Setup dialog theme
        self._setup_dialog_theme(dlg)

        # Main frame
        main_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_label = ctk.CTkLabel(
            main_frame,
            text="Choose import method:",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.COLORS["text"],
        )
        title_label.pack(pady=(0, 20))

        # Button for file import
        def import_from_file():
            dlg.destroy()
            self._import_from_file()

        file_btn = ctk.CTkButton(
            main_frame,
            text="Import from Wallet File",
            command=import_from_file,
            width=320,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["primary"],
            hover_color=self.COLORS["hover"],
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#000000",
        )
        file_btn.pack(pady=10)

        # Button for private key import
        def import_from_key():
            dlg.destroy()
            self._import_from_private_key()

        key_btn = ctk.CTkButton(
            main_frame,
            text="Import from Private Key",
            command=import_from_key,
            width=320,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["primary"],
            hover_color=self.COLORS["hover"],
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#000000",
        )
        key_btn.pack(pady=10)

        # Button for mnemonic import (optional)
        def import_from_mnemonic():
            dlg.destroy()
            self._import_from_mnemonic()

        mnemonic_btn = ctk.CTkButton(
            main_frame,
            text="Import from Mnemonic",
            command=import_from_mnemonic,
            width=320,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["primary"],
            hover_color=self.COLORS["hover"],
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#000000",
        )
        mnemonic_btn.pack(pady=10)

        # Cancel button
        cancel_btn = ctk.CTkButton(
            main_frame,
            text="Cancel",
            command=dlg.destroy,
            width=320,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["surface"],
            hover_color=self.COLORS["text_secondary"],
            font=ctk.CTkFont(size=13),
            text_color=self.COLORS["text"],
        )
        cancel_btn.pack(pady=10)

        # Center dialog
        dlg.update_idletasks()
        width = dlg.winfo_width()
        height = dlg.winfo_height()
        x = self.window.winfo_x() + (self.window.winfo_width() // 2) - (width // 2)
        y = self.window.winfo_y() + (self.window.winfo_height() // 2) - (height // 2)
        dlg.geometry(f"{width}x{height}+{x}+{y}")

        dlg.wait_window()

    def _import_from_file(self):
        """Import wallet from wallet file"""
        file_path = filedialog.askopenfilename(
            title="Select Wallet File",
            filetypes=(("Encrypted Wallet Files", "*.hagoi"), ("All files", "*.*")),
        )
        if not file_path:
            self.status_label.configure(text="Import cancelled", text_color="orange")
            self.window.after(3000, self._clear_status_after_delay)
            return

        # Get password
        result = self.show_password_dialog(action="import")
        if result["cancelled"] or not result["password"]:
            self.status_label.configure(text="Import cancelled", text_color="orange")
            self.window.after(3000, self._clear_status_after_delay)
            return

        # Load the wallet
        wallet_data = self.load_wallet_from_encrypted_file(
            file_path, result["password"]
        )
        if isinstance(wallet_data, str):  # Error message
            self.status_label.configure(text=wallet_data, text_color="red")
            self.window.after(3000, self._clear_status_after_delay)
            return

        # Set as current wallet
        self.current_wallet = wallet_data
        self.public_key_label.configure(
            text=f"Public Key: {self.current_wallet['public_key']}"
        )

        # Load transaction history
        print(
            f"Loading transaction history for public key: {self.current_wallet['public_key']}"
        )
        self.transaction_history = self._load_transaction_history(
            self.current_wallet["public_key"]
        )
        print(f"Loaded {len(self.transaction_history)} transactions")

        self.update_balance()
        self.update_wallet_status()
        self._refresh_history_display()
        self.status_label.configure(text="", text_color="green")
        self.window.after(3000, self._clear_status_after_delay)

    def _import_from_private_key(self):
        """Import wallet from private key"""
        dlg = ctk.CTkToplevel(self.window)
        dlg.title("Import Private Key")
        dlg.minsize(360, 280)
        dlg.transient(self.window)
        dlg.grab_set()

        # Setup dialog theme
        self._setup_dialog_theme(dlg)

        # Main frame
        main_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        key_var = ctk.StringVar()
        error_var = ctk.StringVar()

        # Title
        title_label = ctk.CTkLabel(
            main_frame,
            text="Enter your private key (base58):",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.COLORS["text"],
        )
        title_label.pack(pady=(0, 20))

        # Private key entry
        key_entry = ctk.CTkEntry(
            main_frame,
            width=320,
            height=40,
            textvariable=key_var,
            font=ctk.CTkFont(size=13),
            fg_color=self.COLORS["surface"],
            border_color=self.COLORS["primary"],
            text_color=self.COLORS["text"],
        )
        key_entry.pack(pady=10)
        key_entry.focus()

        # Error label
        error_label = ctk.CTkLabel(
            main_frame,
            textvariable=error_var,
            text_color=self.COLORS["error"],
            wraplength=320,
            font=ctk.CTkFont(size=12),
        )
        error_label.pack(pady=10)

        def on_submit():
            pk = key_var.get().strip()
            if not pk:
                error_var.set("Private key cannot be empty")
                return

            try:
                decoded = base58.b58decode(pk)
                keypair = Keypair.from_secret_key(decoded)
                pub = str(keypair.public_key)
                print(f"Importing wallet with public key: {pub}")
                self.current_wallet = {"private_key": pk, "public_key": pub}
                self.public_key_label.configure(text=f"Public Key: {pub}")

                # Load transaction history
                print("Loading transaction history...")
                self.transaction_history = self._load_transaction_history(pub)
                print(f"Loaded {len(self.transaction_history)} transactions")

                self.update_balance()
                self.update_wallet_status()
                self._refresh_history_display()
                self.status_label.configure(text="", text_color="green")
                self.window.after(3000, self._clear_status_after_delay)
                dlg.destroy()
            except Exception as e:
                error_var.set(f"Invalid private key: {str(e)}")
                print(f"Error importing wallet: {str(e)}")

        # Buttons frame
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)

        # Submit button
        submit_btn = ctk.CTkButton(
            button_frame,
            text="Import",
            command=on_submit,
            width=120,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["primary"],
            hover_color=self.COLORS["hover"],
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#000000",
        )
        submit_btn.pack(side="left", padx=8)

        # Cancel button
        cancel_btn = ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=dlg.destroy,
            width=120,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["surface"],
            hover_color=self.COLORS["text_secondary"],
            font=ctk.CTkFont(size=13),
            text_color=self.COLORS["text"],
        )
        cancel_btn.pack(side="left", padx=8)

        # Center dialog
        dlg.update_idletasks()
        width = dlg.winfo_width()
        height = dlg.winfo_height()
        x = self.window.winfo_x() + (self.window.winfo_width() // 2) - (width // 2)
        y = self.window.winfo_y() + (self.window.winfo_height() // 2) - (height // 2)
        dlg.geometry(f"{width}x{height}+{x}+{y}")

        dlg.wait_window()

    def _import_from_mnemonic(self):
        """Import wallet from mnemonic phrase"""
        dlg = ctk.CTkToplevel(self.window)
        dlg.title("Import from Mnemonic")
        dlg.minsize(360, 400)
        dlg.transient(self.window)
        dlg.grab_set()

        # Setup dialog theme
        self._setup_dialog_theme(dlg)

        # Main frame
        main_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_label = ctk.CTkLabel(
            main_frame,
            text="Enter your mnemonic phrase:",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.COLORS["text"],
        )
        title_label.pack(pady=(0, 20))

        # Mnemonic entry
        mnemonic_text = ctk.CTkTextbox(
            main_frame,
            width=320,
            height=100,
            font=ctk.CTkFont(size=13),
            fg_color=self.COLORS["surface"],
            border_color=self.COLORS["primary"],
            text_color=self.COLORS["text"],
        )
        mnemonic_text.pack(pady=10)

        # Passphrase entry (optional)
        passphrase_label = ctk.CTkLabel(
            main_frame,
            text="Passphrase (optional):",
            font=ctk.CTkFont(size=14),
            text_color=self.COLORS["text"],
        )
        passphrase_label.pack(pady=(10, 5), anchor="w")

        passphrase_entry = ctk.CTkEntry(
            main_frame,
            width=320,
            height=40,
            font=ctk.CTkFont(size=13),
            fg_color=self.COLORS["surface"],
            border_color=self.COLORS["primary"],
            text_color=self.COLORS["text"],
            show="*",  # Sembunyikan passphrase
        )
        passphrase_entry.pack(pady=5)

        # Error label
        error_var = ctk.StringVar()
        error_label = ctk.CTkLabel(
            main_frame,
            textvariable=error_var,
            text_color=self.COLORS["error"],
            wraplength=320,
            font=ctk.CTkFont(size=12),
        )
        error_label.pack(pady=10)

        def on_submit():
            mnemonic = mnemonic_text.get("1.0", "end-1c").strip()
            passphrase = passphrase_entry.get().strip()

            if not mnemonic:
                error_var.set("Mnemonic phrase cannot be empty")
                return

            try:
                # Import wallet dari mnemonic
                wallet_data = self.wallet.import_from_mnemonic(mnemonic, passphrase)
                
                self.current_wallet = wallet_data
                self.public_key_label.configure(text=f"Public Key: {wallet_data['public_key']}")

                # Load transaction history
                print("Loading transaction history...")
                self.transaction_history = self._load_transaction_history(wallet_data['public_key'])
                print(f"Loaded {len(self.transaction_history)} transactions")

                self.update_balance()
                self.update_wallet_status()
                self._refresh_history_display()
                self.status_label.configure(text="Wallet imported successfully!", text_color="green")
                self.window.after(3000, self._clear_status_after_delay)
                dlg.destroy()

            except Exception as e:
                error_var.set(f"Error importing wallet: {str(e)}")
                print(f"Error importing wallet: {str(e)}")

        # Buttons frame
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=20)

        # Submit button
        submit_btn = ctk.CTkButton(
            button_frame,
            text="Import",
            command=on_submit,
            width=120,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["primary"],
            hover_color=self.COLORS["hover"],
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#000000",
        )
        submit_btn.pack(side="left", padx=8)

        # Cancel button
        cancel_btn = ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=dlg.destroy,
            width=120,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["surface"],
            hover_color=self.COLORS["text_secondary"],
            font=ctk.CTkFont(size=13),
            text_color=self.COLORS["text"],
        )
        cancel_btn.pack(side="left", padx=8)

        # Center dialog
        dlg.update_idletasks()
        width = dlg.winfo_width()
        height = dlg.winfo_height()
        x = self.window.winfo_x() + (self.window.winfo_width() // 2) - (width // 2)
        y = self.window.winfo_y() + (self.window.winfo_height() // 2) - (height // 2)
        dlg.geometry(f"{width}x{height}+{x}+{y}")

        dlg.wait_window()

    def load_wallet_from_encrypted_file(self, file_path, password):
        """Load wallet data from encrypted binary file (.wallet)"""
        try:
            with open(file_path, "rb") as file:
                salt = file.read(16)
                encrypted_data = file.read()
            key, _ = WalletEncryption.generate_key_from_password(password, salt)
            f = Fernet(key)
            try:
                decrypted = f.decrypt(encrypted_data)
            except Exception:
                return "Incorrect password or corrupted wallet file"
            try:
                public_key, private_key = decrypted.decode("utf-8").split("|", 1)
            except Exception:
                return "Corrupted wallet file format"
            # Validate private key
            try:
                keypair = Keypair.from_secret_key(base58.b58decode(private_key))
                if str(keypair.public_key) != public_key:
                    return "Wallet file integrity check failed"
            except Exception:
                return "Invalid wallet data"
            return {
                "private_key": private_key,
                "public_key": public_key,
                "salt": salt,
                "encrypted_key": encrypted_data,
            }
        except Exception as e:
            self.status_label.configure(
                text=f"Error loading wallet: {str(e)}", text_color="red"
            )

    def save_current_wallet(self):
        """Save the currently loaded wallet to a JSON file (for backup/import)"""
        self._update_activity_timestamp()
        if not self.current_wallet:
            self.status_label.configure(text="No wallet to save", text_color="orange")
            return
        # Ask for password to encrypt
        result = self.show_password_dialog(action="create")
        if result["cancelled"] or not result["password"]:
            self.status_label.configure(text="Save cancelled", text_color="orange")
            return
        # Ask for file path
        file_path = filedialog.asksaveasfilename(
            title="Save Wallet As",
            defaultextension=".json",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
        )
        if not file_path:
            self.status_label.configure(text="Save cancelled", text_color="orange")
            return
        # Encrypt and save
        try:
            encrypted_data, salt = WalletEncryption.encrypt_data(
                self.current_wallet["private_key"], result["password"]
            )
            wallet_file_data = {
                "public_key": self.current_wallet["public_key"],
                "encrypted_key": base64.b64encode(encrypted_data).decode("utf-8"),
                "salt": base64.b64encode(salt).decode("utf-8"),
            }
            with open(file_path, "w") as f:
                json.dump(wallet_file_data, f, indent=2)
            self.status_label.configure(
                text=f"Wallet saved to {os.path.basename(file_path)}",
                text_color="green",
            )
        except Exception as e:
            self.status_label.configure(
                text=f"Error saving wallet: {str(e)}", text_color="red"
            )

    def logout_wallet(self):
        """Logout from current wallet with proper cleanup"""
        try:
            # Clear current wallet data
            self.current_wallet = None

            # Update UI elements if they exist
            if hasattr(self, "balance_label") and self.balance_label.winfo_exists():
                self.balance_label.configure(text="0 SOL")

            if (
                hasattr(self, "usd_balance_label")
                and self.usd_balance_label.winfo_exists()
            ):
                self.usd_balance_label.configure(text="≈ $0.00 USD")

            if hasattr(self, "status_label") and self.status_label.winfo_exists():
                self.status_label.configure(text="Logged out", text_color="orange")

            # Clear transfer window elements if they exist
            if hasattr(self, "recipient_entry") and self.recipient_entry.winfo_exists():
                self.recipient_entry.delete(0, tk.END)

            if hasattr(self, "amount_entry") and self.amount_entry.winfo_exists():
                self.amount_entry.delete(0, tk.END)

            if hasattr(self, "transfer_status") and self.transfer_status.winfo_exists():
                self.transfer_status.configure(text="")

            # Clear history
            if hasattr(self, "history_text") and self.history_text.winfo_exists():
                self.history_text.delete(1.0, tk.END)

            # Update wallet status
            self.update_wallet_status()

        except Exception as e:
            print(f"Error during logout: {str(e)}")
            # Continue with logout even if there are UI errors
            self.current_wallet = None

    def copy_public_key_to_clipboard(self):
        """Copy the current wallet's public key to clipboard"""
        if not self.current_wallet:
            self.status_label.configure(text="No wallet loaded", text_color="orange")
            self.window.after(3000, self._clear_status_after_delay)
            return

        try:
            self.window.clipboard_clear()
            self.window.clipboard_append(self.current_wallet["public_key"])
            self.status_label.configure(
                text="Public key copied to clipboard!", text_color="green"
            )
            self.window.after(3000, self._clear_status_after_delay)
        except Exception as e:
            self.status_label.configure(
                text=f"Error copying to clipboard: {str(e)}", text_color="red"
            )
            self.window.after(3000, self._clear_status_after_delay)

    def update_balance(self):
        """Update the displayed balance for the current wallet and calculate USD value"""
        if not self.current_wallet:
            self.balance_label.configure(text="0 SOL")
            self.usd_balance_label.configure(text="≈ $0.00 USD")
            return

        try:
            print("Updating balance...")
            balance = self.wallet.get_balance(self.current_wallet["public_key"])
            print(f"Retrieved balance: {balance} SOL")

            if isinstance(balance, float):
                # Update SOL balance
                self.balance_label.configure(text=f"{balance:.4f} SOL")
                print(f"Updated SOL balance display: {balance:.4f} SOL")

                # Get current price if not available
                if self.current_sol_price is None:
                    print("Current price not available, fetching new price...")
                    self.current_sol_price = self.get_sol_price()

                # Update USD balance
                if self.current_sol_price is not None:
                    usd_value = balance * self.current_sol_price
                    self.usd_balance_label.configure(text=f"≈ ${usd_value:.2f} USD")
                    print(f"Updated USD balance: ${usd_value:.2f}")
                else:
                    print("Failed to get current price")
                    self.usd_balance_label.configure(text="≈ $0.00 USD")
            else:
                print(f"Error getting balance: {balance}")
                self.balance_label.configure(text="Balance: Error loading")
                self.usd_balance_label.configure(text="≈ $0.00 USD")
                self.status_label.configure(text=str(balance), text_color="red")
        except Exception as e:
            print(f"Error in update_balance: {str(e)}")
            self.balance_label.configure(text="Balance: Error loading")
            self.usd_balance_label.configure(text="≈ $0.00 USD")
            self.status_label.configure(
                text=f"Error updating balance: {str(e)}", text_color="red"
            )

    def _safe_update_price_chart(self, current_price):
        """Updates the price chart and USD balance in the main thread with the given price"""
        try:
            print(f"Updating price chart with price: {current_price}")

            if current_price is None:
                print("Warning: Received None price in _safe_update_price_chart")
                return

            # Update current price
            self.current_sol_price = current_price
            print(f"Updated current_sol_price to: {current_price}")

            # Update price label in chart window
            if hasattr(self, "price_label") and self.price_label.winfo_exists():
                self.price_label.configure(
                    text=f"Current SOL Price: ${current_price:.2f}",
                    text_color=self.COLORS["text"],
                )
                print(f"Updated chart price label: ${current_price:.2f}")

            # Update USD balance in main window
            if self.current_wallet and hasattr(self, "balance_label"):
                try:
                    sol_balance_text = self.balance_label.cget("text")
                    print(f"Current SOL balance text: {sol_balance_text}")

                    # Extract numerical balance
                    sol_balance_str = sol_balance_text.replace(" SOL", "").strip()
                    print(f"Extracted SOL balance: {sol_balance_str}")

                    if sol_balance_str and sol_balance_str not in [
                        "Error loading",
                        "0",
                    ]:
                        sol_balance = float(sol_balance_str)
                        usd_value = sol_balance * current_price
                        self.usd_balance_label.configure(text=f"≈ ${usd_value:.2f} USD")
                        print(f"Updated USD balance: ${usd_value:.2f}")
                    else:
                        print("Invalid balance text")
                        self.usd_balance_label.configure(text="≈ $0.00 USD")
                except Exception as e:
                    print(f"Error updating USD balance: {str(e)}")
                    self.usd_balance_label.configure(text="≈ $0.00 USD")

        except Exception as e:
            print(f"Error in _safe_update_price_chart: {str(e)}")
            if hasattr(self, "price_label") and self.price_label.winfo_exists():
                self.price_label.configure(
                    text="SOL Price: Error updating", text_color=self.COLORS["error"]
                )
            if hasattr(self, "usd_balance_label"):
                self.usd_balance_label.configure(text="≈ $0.00 USD")

    def open_transfer_window(self):
        """Open a separate window for transferring SOL."""
        if not self.current_wallet:
            messagebox.showwarning(
                "No Wallet Loaded",
                "Please create or import a wallet first to transfer SOL.",
            )
            return

        transfer_window = ctk.CTkToplevel(self.window)
        transfer_window.title("Transfer SOL")
        transfer_window.geometry(
            "370x630"
        )  # Menambah tinggi jendela agar tidak terlalu sempit
        transfer_window.transient(self.window)
        transfer_window.grab_set()
        transfer_window.resizable(False, False)

        # Setup dialog theme
        self._setup_dialog_theme(transfer_window)

        # Build UI inside the new window
        self.build_transfer_ui(transfer_window)

        transfer_window.wait_window()

    def build_transfer_ui(self, parent_frame):
        """Builds the UI elements for the transfer window."""
        # Main frame
        main_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_label = ctk.CTkLabel(
            main_frame,
            text="Transfer SOL",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=self.COLORS["text"],
        )
        title_label.pack(pady=(0, 20))

        # Current Balance Display
        self.balance_frame = ctk.CTkFrame(
            main_frame, fg_color=self.COLORS["surface"], corner_radius=8
        )
        self.balance_frame.pack(fill="x", pady=(0, 20))

        # Label untuk menampung gambar latar belakang
        self.balance_background_label = ctk.CTkLabel(self.balance_frame, text="")
        self.balance_background_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Reset last background size untuk memaksa reload gambar
        if hasattr(self, "_last_background_size"):
            delattr(self, "_last_background_size")

        # Jadwalkan pemuatan gambar setelah frame di-layout
        self.balance_frame.after(
            100, lambda: self.load_and_place_background_image(force_reload=True)
        )

        balance_label = ctk.CTkLabel(
            self.balance_frame,
            text="Available Balance:",
            font=ctk.CTkFont(size=14),
            text_color=self.COLORS["text_secondary"],
            fg_color="transparent",  # Pastikan background transparan
        )
        # Gunakan place untuk menempatkan label teks di atas gambar latar belakang
        balance_label.place(x=15, y=15)  # Sesuaikan posisi

        self.transfer_balance_label = ctk.CTkLabel(
            self.balance_frame,
            text="0 SOL",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=self.COLORS["text"],
            fg_color="transparent",  # Pastikan background transparan
        )
        # Gunakan place untuk menempatkan label teks di atas gambar latar belakang
        # Posisikan di kanan, 10px dari kanan frame
        self.transfer_balance_label.place(relx=1.0, x=-15, y=15, anchor="ne")

        # Recipient Address
        recipient_label = ctk.CTkLabel(
            main_frame,
            text="Recipient Address:",
            font=ctk.CTkFont(size=14),
            text_color=self.COLORS["text"],
        )
        recipient_label.pack(pady=(0, 5), anchor="w")

        self.recipient_entry = ctk.CTkEntry(
            main_frame,
            height=40,
            corner_radius=8,
            font=ctk.CTkFont(size=13),
            fg_color=self.COLORS["surface"],
            border_color=self.COLORS["primary"],
            text_color=self.COLORS["text"],
            placeholder_text="Enter Solana address",
        )
        self.recipient_entry.pack(pady=5, fill="x")

        # Amount
        # Frame untuk Amount dan Max button, termasuk label
        amount_container_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        amount_container_frame.pack(pady=(10, 5), fill="x")

        # Label Amount
        amount_label = ctk.CTkLabel(
            amount_container_frame,  # Buat label di dalam container frame
            text="Amount (SOL):",
            font=ctk.CTkFont(size=14),
            text_color=self.COLORS["text"],
        )
        amount_label.pack(side="left", padx=(0, 10))

        # Frame untuk Entry dan Max button
        amount_input_frame = ctk.CTkFrame(
            amount_container_frame, fg_color="transparent"
        )
        amount_input_frame.pack(side="left", fill="x", expand=True)

        # Amount Entry
        self.amount_entry = ctk.CTkEntry(
            amount_input_frame,  # Buat entry di dalam input frame
            height=40,
            corner_radius=8,
            font=ctk.CTkFont(size=13),
            fg_color=self.COLORS["surface"],
            border_color=self.COLORS["primary"],
            text_color=self.COLORS["text"],
            placeholder_text="Enter amount",
        )
        self.amount_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        # Max Button
        self.max_amount_btn = ctk.CTkButton(
            amount_input_frame,  # Buat button di dalam input frame
            text="Max",
            command=self.set_max_amount,
            width=60,  # Lebar disesuaikan
            height=40,  # Tinggi sama dengan entry
            corner_radius=8,
            fg_color=self.COLORS["primary"],
            hover_color=self.COLORS["hover"],
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#000000",
        )
        self.max_amount_btn.pack(side="right")

        # Progress Frame
        self.progress_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        self.progress_frame.pack(fill="x", pady=10)

        self.progress_bar = ctk.CTkProgressBar(
            self.progress_frame,
            width=320,
            height=4,
            corner_radius=2,
            fg_color=self.COLORS["surface"],
            progress_color=self.COLORS["primary"],
        )
        self.progress_bar.pack(pady=5)
        self.progress_bar.set(0)
        self.progress_frame.pack_forget()  # Hide initially

        # Send Button
        self.send_btn = ctk.CTkButton(
            main_frame,
            text="Send SOL",
            command=self.send_sol,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["primary"],
            hover_color=self.COLORS["hover"],
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#000000",
        )
        self.send_btn.pack(pady=20, fill="x")

        # Transfer Status
        self.transfer_status = ctk.CTkLabel(
            main_frame,
            text="",
            text_color=self.COLORS["success"],
            wraplength=360,
            font=ctk.CTkFont(size=12),
        )
        self.transfer_status.pack(pady=10)

        # Update balance display
        self._update_transfer_balance()

    def _update_transfer_balance(self):
        """Update the balance display in transfer window"""
        if self.current_wallet:
            balance = self.wallet.get_balance(self.current_wallet["public_key"])
            if isinstance(balance, float):
                self.transfer_balance_label.configure(text=f"{balance:.4f} SOL")
            else:
                self.transfer_balance_label.configure(text="Error loading balance")

    def send_sol(self):
        """Send SOL to another wallet"""
        self._update_activity_timestamp()

        print("[DEBUG] Starting send_sol function")
        print(f"[DEBUG] Current wallet state: {self.current_wallet}")

        # Validate wallet
        if not self.current_wallet:
            error_msg = "Please create or import a wallet first!"
            print(f"[ERROR] {error_msg}")
            self.transfer_status.configure(text=error_msg, text_color="red")
            return

        # Get and validate inputs
        recipient = self.recipient_entry.get().strip()
        amount_str = self.amount_entry.get().strip()

        print(f"[DEBUG] Validating inputs: recipient={recipient}, amount={amount_str}")

        # Validate recipient address
        if not recipient:
            error_msg = "Please enter a recipient address."
            print(f"[ERROR] {error_msg}")
            self.transfer_status.configure(text=error_msg, text_color="red")
            return

        try:
            PublicKey(recipient)
        except Exception as e:
            error_msg = f"Invalid Solana address format: {str(e)}"
            print(f"[ERROR] {error_msg}")
            self.transfer_status.configure(
                text="Invalid Solana address format.", text_color="red"
            )
            return

        # Validate amount
        try:
            amount = float(amount_str)
            if amount <= 0:
                error_msg = "Amount must be greater than 0."
                print(f"[ERROR] {error_msg}")
                self.transfer_status.configure(text=error_msg, text_color="red")
                return
        except ValueError as e:
            error_msg = f"Invalid amount format: {str(e)}"
            print(f"[ERROR] {error_msg}")
            self.transfer_status.configure(
                text="Please enter a valid amount.", text_color="red"
            )
            return

        # Get current balance
        try:
            current_balance = self.wallet.get_balance(self.current_wallet["public_key"])
            print(f"[DEBUG] Current balance: {current_balance}")

            if not isinstance(current_balance, float):
                error_msg = f"Error getting balance: {str(current_balance)}"
                print(f"[ERROR] {error_msg}")
                self.transfer_status.configure(text=error_msg, text_color="red")
                return

            # Check if balance is sufficient
            if amount > current_balance:
                error_msg = (
                    f"Insufficient balance. Available: {current_balance:.4f} SOL"
                )
                print(f"[ERROR] {error_msg}")
                self.transfer_status.configure(text=error_msg, text_color="red")
                return
        except Exception as e:
            error_msg = f"Error checking balance: {str(e)}"
            print(f"[ERROR] {error_msg}")
            self.transfer_status.configure(
                text="Error checking balance.", text_color="red"
            )
            return

        print("[DEBUG] Starting transaction process")

        # Disable UI elements and show progress
        self.send_btn.configure(state="disabled", text="Sending...")
        self.recipient_entry.configure(state="disabled")
        self.amount_entry.configure(state="disabled")
        self.progress_frame.pack(fill="x", pady=10)
        self.progress_bar.set(0.2)
        self.transfer_status.configure(
            text="Preparing transaction...", text_color="orange"
        )

        # Get transfer window reference
        transfer_window = self.send_btn.winfo_toplevel()

        def check_balance_after_transaction(initial_balance, amount, check_count=0):
            """Check balance after transaction to confirm it decreased"""
            if check_count >= 3:  # Stop after 3 checks
                return

            try:
                current_balance = self.wallet.get_balance(
                    self.current_wallet["public_key"]
                )
                print(f"[DEBUG] Balance check {check_count + 1}: {current_balance} SOL")

                if isinstance(current_balance, float):
                    expected_balance = initial_balance - amount
                    if (
                        abs(current_balance - expected_balance) < 0.000001
                    ):  # Allow small floating point differences
                        print(f"[DEBUG] Balance confirmed: {current_balance} SOL")
                        if transfer_window.winfo_exists():
                            transfer_window.after(
                                0,
                                lambda: self.transfer_status.configure(
                                    text=f"Transaction confirmed! New balance: {current_balance:.4f} SOL",
                                    text_color="green",
                                ),
                            )
                    else:
                        print(
                            f"[DEBUG] Balance not yet updated. Expected: {expected_balance}, Got: {current_balance}"
                        )
                        # Schedule next check after 2 seconds
                        transfer_window.after(
                            2000,
                            lambda: check_balance_after_transaction(
                                initial_balance, amount, check_count + 1
                            ),
                        )
            except Exception as e:
                print(f"[ERROR] Error checking balance: {str(e)}")
                # Try again after 2 seconds
                transfer_window.after(
                    2000,
                    lambda: check_balance_after_transaction(
                        initial_balance, amount, check_count + 1
                    ),
                )

        def send_in_thread():
            try:
                print("[DEBUG] Starting transaction thread")
                # Update progress
                if transfer_window.winfo_exists():
                    transfer_window.after(0, lambda: self.progress_bar.set(0.4))
                    transfer_window.after(
                        0,
                        lambda: self.transfer_status.configure(
                            text="Sending transaction...", text_color="orange"
                        ),
                    )

                # Update wallet's current_wallet before sending transaction
                self.wallet.current_wallet = self.current_wallet

                # Send transaction
                print("[DEBUG] Calling send_transaction")
                result = self.wallet.send_transaction(
                    self.current_wallet["private_key"], recipient, amount
                )

                result_text = str(result)
                print(f"[DEBUG] Transaction result: {result_text}")

                if not result_text.lower().startswith("error"):
                    # Update progress
                    if transfer_window.winfo_exists():
                        transfer_window.after(0, lambda: self.progress_bar.set(0.8))
                        transfer_window.after(
                            0,
                            lambda: self.transfer_status.configure(
                                text="Confirming transaction...", text_color="orange"
                            ),
                        )

                    # Add to history and update UI
                    if transfer_window.winfo_exists():
                        transfer_window.after(
                            0,
                            lambda: self._add_to_history(
                                result_text, amount, recipient
                            ),
                        )
                        transfer_window.after(0, lambda: self.progress_bar.set(1.0))
                        transfer_window.after(
                            0,
                            lambda: self.transfer_status.configure(
                                text="Transaction successful! Verifying balance...",
                                text_color="green",
                            ),
                        )

                        # Start balance verification
                        transfer_window.after(
                            1000,
                            lambda: check_balance_after_transaction(
                                current_balance, amount
                            ),
                        )

                        # Update balances after delay
                        transfer_window.after(5000, self.update_balance)
                        transfer_window.after(5000, self._update_transfer_balance)
                else:
                    print(f"[ERROR] Transaction failed: {result_text}")
                    if transfer_window.winfo_exists():
                        transfer_window.after(
                            0,
                            lambda: self.transfer_status.configure(
                                text=result_text, text_color="red"
                            ),
                        )

            except Exception as e:
                error_msg = f"Error in transaction thread: {str(e)}"
                print(f"[ERROR] {error_msg}")
                if transfer_window.winfo_exists():
                    transfer_window.after(
                        0,
                        lambda: self.transfer_status.configure(
                            text=f"{error_msg}", text_color="red"
                        ),
                    )
            finally:
                print("[DEBUG] Cleaning up transaction thread")
                # Re-enable UI elements
                if transfer_window.winfo_exists():
                    transfer_window.after(
                        0,
                        lambda: self.send_btn.configure(
                            state="normal", text="Send SOL"
                        ),
                    )
                    transfer_window.after(
                        0, lambda: self.recipient_entry.configure(state="normal")
                    )
                    transfer_window.after(
                        0, lambda: self.amount_entry.configure(state="normal")
                    )
                    transfer_window.after(0, lambda: self.progress_frame.pack_forget())
                    transfer_window.after(0, lambda: self.progress_bar.set(0))

        threading.Thread(target=send_in_thread, daemon=True).start()

    def set_max_amount(self):
        """Set the transfer amount to the maximum possible (balance - estimated fee)"""
        if not self.current_wallet:
            self.transfer_status.configure(
                text="Error: No wallet loaded to check balance.", text_color="red"
            )
            return

        try:
            # Get current balance
            current_balance = self.wallet.get_balance(self.current_wallet["public_key"])

            if not isinstance(current_balance, float):
                self.transfer_status.configure(
                    text=f"Error getting balance: {str(current_balance)}",
                    text_color="red",
                )
                return

            # Estimate fee (using the same estimate as in send_transaction)
            # Solana fees are dynamic, but this is a reasonable small estimate
            estimated_fee_sol = 0.000005  # ~5000 lamports

            # Calculate max transferable amount
            max_amount = current_balance - estimated_fee_sol

            if max_amount < 0:
                max_amount = 0  # Cannot transfer a negative amount

            # Update the amount entry field
            self.amount_entry.delete(0, tk.END)
            self.amount_entry.insert(0, f"{max_amount:.9f}")  # Use enough precision

            self.transfer_status.configure(
                text="Max amount calculated.", text_color="green"
            )

        except Exception as e:
            error_msg = f"Error calculating max amount: {str(e)}"
            print(f"[ERROR] {error_msg}")
            self.transfer_status.configure(text=error_msg, text_color="red")

    def open_chart_window(self):
        """Open a separate window for the price chart."""
        chart_window = ctk.CTkToplevel(self.window)
        chart_window.title("SOL Price Chart")
        chart_window.geometry("600x500")
        chart_window.transient(self.window)
        chart_window.grab_set()

        # Setup dialog theme
        self._setup_dialog_theme(chart_window)

        # Build UI inside the new window
        self.build_chart_ui(chart_window)

        # Load and display 1-day chart data by default
        self.update_chart_history(1)  # Load 1 day data by default

        chart_window.wait_window()

    def build_chart_ui(self, parent_frame):
        """Builds the UI elements for the price chart window."""
        # Price Chart Frame
        chart_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        chart_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Current Price Label
        self.price_label = ctk.CTkLabel(
            chart_frame,
            text="Current SOL Price: Loading...",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        self.price_label.pack(pady=(0, 10))

        # Create matplotlib figure dengan style dark
        plt.style.use("dark_background")
        self.fig, self.ax = plt.subplots(figsize=(5, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

        # Configure plot appearance for dark theme
        self.ax.set_facecolor(self.COLORS["surface"])  # Background area plot
        self.fig.patch.set_facecolor(self.COLORS["background"])  # Background figure

        self.ax.tick_params(
            axis="x", colors=self.COLORS["text_secondary"]
        )  # Warna tick sumbu X
        self.ax.tick_params(
            axis="y", colors=self.COLORS["text_secondary"]
        )  # Warna tick sumbu Y

        self.ax.spines["bottom"].set_color(
            self.COLORS["text_secondary"]
        )  # Warna garis sumbu
        self.ax.spines["left"].set_color(self.COLORS["text_secondary"])
        self.ax.spines["top"].set_visible(False)  # Hilangkan garis atas dan kanan
        self.ax.spines["right"].set_visible(False)

        # Add grid lines
        self.ax.grid(
            True, linestyle="--", alpha=0.3, color=self.COLORS["text_secondary"]
        )

    def update_wallet_status(self):
        """Update the wallet status in the menu"""
        if self.current_wallet:
            public_key = self.current_wallet["public_key"]
            shortened_key = f"{public_key[:8]}...{public_key[-8:]}"
            self.wallet_status_label.configure(text=f"Wallet: {shortened_key}")
        else:
            self.wallet_status_label.configure(text="No wallet loaded")

    def on_closing(self):
        """Handle window closing event"""
        # Add a flag to indicate we're shutting down
        self.is_closing = True
        self.is_logging_out = True

        # Clear sensitive data
        if self.current_wallet:
            for key in self.current_wallet:
                if isinstance(self.current_wallet[key], str):
                    # Overwrite with random bytes before deleting
                    random_bytes = os.urandom(len(self.current_wallet[key]))
                    self.current_wallet[key] = "".join(
                        [chr(b % 128) for b in random_bytes]
                    )
            self.current_wallet = None

        # Destroy the window
        self.window.destroy()

        # Terminate any remaining threads - necessary for clean exit
        os._exit(0)

    def _refresh_history_display(self):
        """Refresh the transaction history display"""
        # Clear existing entries
        for widget in self.history_scrollable_frame.winfo_children():
            widget.destroy()

        if not self.transaction_history:
            lbl = ctk.CTkLabel(
                self.history_scrollable_frame,
                text="No transactions yet",
                font=ctk.CTkFont(size=14),
                text_color="gray",
            )
            lbl.pack(pady=10)
        else:
            # Show latest first
            for entry in reversed(self.transaction_history):
                lbl = ctk.CTkLabel(
                    self.history_scrollable_frame,
                    text=entry,
                    wraplength=300,
                    justify="left",
                    anchor="w",
                    font=ctk.CTkFont(size=12),
                )
                lbl.pack(fill="x", pady=2, padx=10)

    def get_sol_price(self):
        """Get the current price of SOL"""
        try:
            print("Attempting to get SOL price...")
            response = requests.get(
                "https://api.coingecko.com/api/v3/simple/price",
                params={"ids": "solana", "vs_currencies": "usd"},
                timeout=5,
            )

            print(f"API Response Status: {response.status_code}")

            if response.status_code != 200:
                print(f"API Error: Status {response.status_code}")
                return self.current_sol_price

            data = response.json()
            print(f"API Response Data: {data}")

            if "solana" not in data or "usd" not in data["solana"]:
                print("Invalid API Response Format")
                return self.current_sol_price

            price = data["solana"]["usd"]
            print(f"Retrieved SOL Price: ${price}")

            # Update current price
            self.current_sol_price = price
            return price

        except Exception as e:
            print(f"Error in get_sol_price: {str(e)}")
            return self.current_sol_price

    def get_sol_historical_price(self, days: int):
        """Get historical price data for SOL for a given number of days."""
        # Implement local rate limiting for chart data
        current_time = time.time()
        if (
            current_time - self._last_chart_price_call < 60
        ):  # 60 seconds cooldown for chart
            return self.last_chart_data  # Return cached chart data if available

        try:
            end_time = int(time.time())
            start_time = int(time.time()) - (days * 24 * 60 * 60)
            vs_currency = "usd"
            api_url = f"https://api.coingecko.com/api/v3/coins/solana/market_chart/range?vs_currency={vs_currency}&from={start_time}&to={end_time}"

            response = requests.get(api_url, timeout=10)

            if response.status_code != 200:
                print(
                    f"CoinGecko historical API error: Received status code {response.status_code}"
                )
                return self.last_chart_data  # Return cached data on error

            data = response.json()
            if "prices" not in data or not data["prices"]:
                print("Invalid historical data format from CoinGecko API")
                return self.last_chart_data  # Return cached data on error

            self._last_chart_price_call = current_time
            return data["prices"]

        except Exception as e:
            print(f"Error getting historical SOL price: {str(e)}")
            return self.last_chart_data  # Return cached data on error

    def _wait_for_api_cool_down(self):
        """Waits if necessary to respect local API call rate limit."""
        min_interval = 30  # Minimum seconds between API calls
        if self._last_api_call_time is not None:
            elapsed = time.time() - self._last_api_call_time
            if elapsed < min_interval:
                wait_time = min_interval - elapsed
                print(f"Waiting {wait_time:.2f} seconds to respect API cool-down...")
                time.sleep(wait_time)

    def run(self):
        """Start the application main loop"""
        # Start session timer check
        self._check_session_timeout()

        # Start price update thread
        if self.price_thread is None or not self.price_thread.is_alive():
            print("Starting price update thread...")
            self.price_thread = threading.Thread(
                target=self.update_price_periodically, daemon=True
            )
            self.price_thread.start()

        # Start balance check thread
        if self.balance_thread is None or not self.balance_thread.is_alive():
            print("Starting balance check thread...")
            self.balance_thread = threading.Thread(
                target=self.check_balance_periodically, daemon=True
            )
            self.balance_thread.start()

        self.window.mainloop()

    def check_balance_periodically(self):
        """Check balance periodically and update if changed"""
        while not self.is_closing and not self.is_logging_out:
            try:
                if self.current_wallet:
                    # Get current balance
                    current_balance = self.wallet.get_balance(
                        self.current_wallet["public_key"]
                    )

                    if isinstance(current_balance, float):
                        # Check if balance has changed
                        if (
                            self.last_balance is None
                            or abs(current_balance - self.last_balance) > 0.000001
                        ):  # Toleransi untuk floating point
                            print(
                                f"Balance changed from {self.last_balance} to {current_balance}"
                            )
                            self.last_balance = current_balance

                            # Update UI on main thread
                            self.window.after(0, self.update_balance)

                            # Refresh transaction history
                            self.window.after(
                                0, lambda: self._refresh_history_display()
                            )
                    else:
                        print(f"Error getting balance: {current_balance}")

                # Wait for 10 seconds before next check
                for _ in range(10):
                    if self.is_closing or self.is_logging_out:
                        break
                    time.sleep(1)

            except Exception as e:
                print(f"Error in balance check thread: {str(e)}")
                time.sleep(10)  # Wait before retrying on error

    def _check_session_timeout(self):
        """Check if the session has timed out due to inactivity"""
        # Skip if we're in the process of closing the app
        if self.is_closing:
            return

        if self.current_wallet:
            time_since_activity = (
                datetime.now() - self.last_activity_time
            ).total_seconds() / 60
            if time_since_activity >= self.session_timeout_minutes:
                self.logout_wallet()
                self.status_label.configure(
                    text=f"Logged out due to {self.session_timeout_minutes} minutes of inactivity",
                    text_color="orange",
                )
        # Check again in 30 seconds
        self.window.after(30000, self._check_session_timeout)

    def _update_activity_timestamp(self):
        """Update the timestamp of last user activity"""
        self.last_activity_time = datetime.now()

    def show_password_dialog(self, action="create"):
        """Show a dialog to enter password"""
        dialog = ctk.CTkToplevel(self.window)
        dialog.title("Enter Password")
        dialog.minsize(320, 300)  # Ukuran minimum yang lebih kecil
        dialog.geometry("320x300")  # Ukuran awal yang lebih kecil
        dialog.resizable(False, False)  # Nonaktifkan resize
        dialog.transient(self.window)
        dialog.grab_set()

        # Setup dialog theme
        self._setup_dialog_theme(dialog)

        # Main frame
        main_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=16, pady=16)  # Kurangi padding

        password = ctk.StringVar()
        confirm_password = ctk.StringVar() if action == "create" else None
        error_var = ctk.StringVar()
        result = {"password": None, "cancelled": True}

        def validate_password(pwd):
            """Validate password strength"""
            if len(pwd) < 8:
                return "Password must be at least 8 characters long"
            if not any(c.isupper() for c in pwd):
                return "Password must contain at least one uppercase letter"
            if not any(c.islower() for c in pwd):
                return "Password must contain at least one lowercase letter"
            if not any(c.isdigit() for c in pwd):
                return "Password must contain at least one number"
            if not any(c in "!@#$%^&*()_+-={}[]|\\:;\"'<>,.?/~`" for c in pwd):
                return "Password must contain at least one special character"
            return None

        def on_submit():
            pwd = password.get()
            error_msg = validate_password(pwd)

            if error_msg:
                error_var.set(error_msg)
                return

            if action == "create":
                if pwd != confirm_password.get():
                    error_var.set("Passwords do not match")
                    return

            if not pwd:
                error_var.set("Password cannot be empty")
                return

            error_var.set("")
            result["password"] = pwd
            result["cancelled"] = False
            dialog.destroy()

        def on_cancel():
            dialog.destroy()

        # Title
        title_label = ctk.CTkLabel(
            main_frame,
            text=(
                "Enter password for wallet encryption:"
                if action == "create"
                else "Enter wallet password:"
            ),
            font=ctk.CTkFont(size=14, weight="bold"),  # Ukuran font lebih kecil
            text_color=self.COLORS["text"],
        )
        title_label.pack(pady=(0, 8))  # Kurangi padding

        if action == "create":
            password_hint = ctk.CTkLabel(
                main_frame,
                text="Password must be at least 8 characters with uppercase, lowercase,\nnumber and special character",
                wraplength=280,  # Kurangi lebar wrap
                text_color=self.COLORS["text_secondary"],
                font=ctk.CTkFont(size=11),  # Ukuran font lebih kecil
            )
            password_hint.pack(pady=(0, 4))  # Kurangi padding

        # Password Entry
        password_entry = ctk.CTkEntry(
            main_frame,
            show="*",
            textvariable=password,
            height=36,  # Kurangi tinggi
            corner_radius=8,
            font=ctk.CTkFont(size=12),  # Ukuran font lebih kecil
            fg_color=self.COLORS["surface"],
            border_color=self.COLORS["primary"],
            text_color=self.COLORS["text"],
        )
        password_entry.pack(pady=4, fill="x")  # Kurangi padding
        password_entry.focus()

        if action == "create":
            confirm_label = ctk.CTkLabel(
                main_frame,
                text="Confirm password:",
                font=ctk.CTkFont(size=12),  # Ukuran font lebih kecil
                text_color=self.COLORS["text"],
            )
            confirm_label.pack(pady=(4, 2))  # Kurangi padding

            confirm_entry = ctk.CTkEntry(
                main_frame,
                show="*",
                textvariable=confirm_password,
                height=36,  # Kurangi tinggi
                corner_radius=8,
                font=ctk.CTkFont(size=12),  # Ukuran font lebih kecil
                fg_color=self.COLORS["surface"],
                border_color=self.COLORS["primary"],
                text_color=self.COLORS["text"],
            )
            confirm_entry.pack(pady=2, fill="x")  # Kurangi padding

        # Error label
        error_label = ctk.CTkLabel(
            main_frame,
            textvariable=error_var,
            text_color=self.COLORS["error"],
            wraplength=280,  # Kurangi lebar wrap
            font=ctk.CTkFont(size=11),  # Ukuran font lebih kecil
        )
        error_label.pack(pady=4)  # Kurangi padding

        # Buttons frame
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=8)  # Kurangi padding

        # Submit button
        submit_btn = ctk.CTkButton(
            button_frame,
            text="Submit",
            command=on_submit,
            width=100,  # Kurangi lebar
            height=36,  # Kurangi tinggi
            corner_radius=8,
            fg_color=self.COLORS["primary"],
            hover_color=self.COLORS["hover"],
            font=ctk.CTkFont(size=12, weight="bold"),  # Ukuran font lebih kecil
            text_color="#000000",
        )
        submit_btn.pack(side="left", padx=6)  # Kurangi padding

        # Cancel button
        cancel_btn = ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=on_cancel,
            width=100,  # Kurangi lebar
            height=36,  # Kurangi tinggi
            corner_radius=8,
            fg_color=self.COLORS["surface"],
            hover_color=self.COLORS["text_secondary"],
            font=ctk.CTkFont(size=12),  # Ukuran font lebih kecil
            text_color=self.COLORS["text"],
        )
        cancel_btn.pack(side="left", padx=6)  # Kurangi padding

        # Center dialog
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = self.window.winfo_x() + (self.window.winfo_width() // 2) - (width // 2)
        y = self.window.winfo_y() + (self.window.winfo_height() // 2) - (height // 2)
        dialog.geometry(f"{width}x{height}+{x}+{y}")

        dialog.wait_window()
        return result

    def show_receive_dialog(self):
        """Show dialog with QR code for receiving SOL"""
        if not self.current_wallet:
            messagebox.showwarning(
                "No Wallet Loaded",
                "Please create or import a wallet first to receive SOL.",
            )
            return

        dlg = ctk.CTkToplevel(self.window)
        dlg.title("Receive SOL")
        dlg.minsize(360, 500)  # Perbesar ukuran minimum
        dlg.geometry("360x500")  # Set ukuran awal
        dlg.resizable(False, False)  # Nonaktifkan resize
        dlg.transient(self.window)
        dlg.grab_set()

        # Setup dialog theme
        self._setup_dialog_theme(dlg)

        # Main frame
        main_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_label = ctk.CTkLabel(
            main_frame,
            text="Receive SOL",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.COLORS["text"],
        )
        title_label.pack(pady=(0, 20))

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(self.current_wallet["public_key"])
        qr.make(fit=True)

        # Create QR code image
        qr_image = qr.make_image(fill_color="white", back_color="black")

        # Convert to PhotoImage
        bio = io.BytesIO()
        qr_image.save(bio, format="PNG")
        qr_image = Image.open(bio)
        qr_photo = ImageTk.PhotoImage(qr_image)

        # Display QR code
        qr_label = ctk.CTkLabel(main_frame, image=qr_photo, text="")
        qr_label.image = qr_photo  # Keep a reference
        qr_label.pack(pady=10)

        # Public key display
        key_frame = ctk.CTkFrame(
            main_frame, fg_color=self.COLORS["surface"], corner_radius=8
        )
        key_frame.pack(fill="x", pady=10)

        key_label = ctk.CTkLabel(
            key_frame,
            text=f"Public Key: {self.current_wallet['public_key']}",
            wraplength=300,
            font=ctk.CTkFont(size=12),
            text_color=self.COLORS["text"],
        )
        key_label.pack(pady=10, padx=10)

        # Copy button
        copy_btn = ctk.CTkButton(
            main_frame,
            text="Copy Address",
            command=lambda: self.copy_public_key_to_clipboard(),
            width=320,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["primary"],
            hover_color=self.COLORS["hover"],
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#000000",
        )
        copy_btn.pack(pady=10)

        # Close button
        close_btn = ctk.CTkButton(
            main_frame,
            text="Close",
            command=dlg.destroy,
            width=320,
            height=40,
            corner_radius=8,
            fg_color=self.COLORS["surface"],
            hover_color=self.COLORS["text_secondary"],
            font=ctk.CTkFont(size=13),
            text_color=self.COLORS["text"],
        )
        close_btn.pack(pady=10)

        # Center dialog
        dlg.update_idletasks()
        width = dlg.winfo_width()
        height = dlg.winfo_height()
        x = self.window.winfo_x() + (self.window.winfo_width() // 2) - (width // 2)
        y = self.window.winfo_y() + (self.window.winfo_height() // 2) - (height // 2)
        dlg.geometry(f"{width}x{height}+{x}+{y}")

        dlg.wait_window()

    def update_chart_history(self, days: float):
        """Fetch and update the chart with historical data for the given number of days."""
        print(f"Updating chart for {days} days history...")

        # Show loading text
        self.price_label.configure(
            text="Loading historical data...", text_color=self.COLORS["text"]
        )

        # Clear previous chart immediately for better feedback
        if (
            hasattr(self, "ax")
            and hasattr(self, "canvas")
            and self.canvas.get_tk_widget().winfo_exists()
        ):
            self.ax.clear()
            # Reapply base plot appearance
            self._apply_chart_appearance()
            self.canvas.draw()

        # Cek apakah data chart sudah ada dan masih valid (kurang dari 5 menit)
        current_time = datetime.now()
        if (
            self.last_chart_data is not None
            and self.last_chart_update is not None
            and (current_time - self.last_chart_update).total_seconds() < 300
        ):  # 5 menit
            print("Using cached chart data...")
            self.window.after(
                0, lambda: self._post_fetch_update_chart(self.last_chart_data)
            )
            return

        # Run data fetching in a separate thread
        def fetch_and_update():
            # Convert float days to int for get_sol_historical_price if > 1
            # For <1 day, API automatically provides 5-minutely, so pass 1
            api_days = int(days) if days >= 1 else 1
            historical_data = self.get_sol_historical_price(api_days)

            if historical_data:
                # Simpan data untuk penggunaan selanjutnya
                self.last_chart_data = historical_data
                self.last_chart_update = current_time

            # Call _post_fetch_update_chart on the main thread to handle UI update
            if self.window and self.window.winfo_exists():
                self.window.after(
                    0, lambda: self._post_fetch_update_chart(historical_data)
                )

        threading.Thread(target=fetch_and_update, daemon=True).start()

    def _post_fetch_update_chart(self, historical_data):
        """Handle data after fetching and update UI on the main thread."""
        try:
            # Update chart UI based on data
            if historical_data:
                # Process data: convert timestamps and separate price/time
                time_data = [
                    datetime.fromtimestamp(point[0] / 1000) for point in historical_data
                ]
                price_data = [point[1] for point in historical_data]

                # Update chart UI
                self._update_chart_ui(time_data, price_data)

            else:
                # Handle error or no data (get_sol_historical_price already prints error)
                if self.price_label.winfo_exists():
                    # get_sol_historical_price prints specific errors (like 429)
                    # We can check the text set by get_sol_historical_price if needed,
                    # but displaying a generic failure message might suffice.
                    # Let's check if the error message was already set by get_sol_historical_price
                    current_price_label_text = self.price_label.cget("text")
                    if not current_price_label_text.startswith("API Error:"):
                        self.price_label.configure(
                            text="Failed to load historical data.",
                            text_color=self.COLORS["error"],
                        )

        except Exception as e:
            print(f"Error in _post_fetch_update_chart: {str(e)}")
            if self.price_label.winfo_exists():
                self.price_label.configure(
                    text="An error occurred during chart update.",
                    text_color=self.COLORS["error"],
                )

    def _update_chart_ui(self, time_data, price_data):
        """Update the chart display on the main thread."""
        try:
            if (
                hasattr(self, "ax")
                and hasattr(self, "canvas")
                and self.canvas.get_tk_widget().winfo_exists()
            ):
                self.ax.clear()  # Clear previous plot

                # Plotting with appropriate style
                self.ax.plot(
                    time_data, price_data, color=self.COLORS["primary"], linewidth=1.5
                )  # Garis plot

                # Update title and labels
                self.ax.set_title(
                    "SOL/USD Price History", color=self.COLORS["text"], fontsize=14
                )
                self.ax.set_xlabel(
                    "Time", color=self.COLORS["text_secondary"], fontsize=10
                )
                self.ax.set_ylabel(
                    "Price (USD)", color=self.COLORS["text_secondary"], fontsize=10
                )

                # Reapply chart appearance (grid, colors, etc.)
                self._apply_chart_appearance()

                # Format sumbu X
                self.fig.autofmt_xdate()

                self.canvas.draw()  # Redraw canvas
                print("Chart UI updated.")

            # Update current price label (optional, can keep real-time label separate)
            # Or update it with the last price from historical data
            if price_data and self.price_label.winfo_exists():
                last_price = price_data[-1]
                self.price_label.configure(
                    text=f"Current SOL Price: ${last_price:.2f}",
                    text_color=self.COLORS["text"],
                )

        except Exception as e:
            print(f"Error updating chart UI: {str(e)}")
            if hasattr(self, "price_label") and self.price_label.winfo_exists():
                self.price_label.configure(
                    text="Error displaying chart.", text_color=self.COLORS["error"]
                )

    def _apply_chart_appearance(self):
        """Apply standard chart appearance settings."""
        if not hasattr(self, "ax"):
            return  # Ensure axes exist
        # Configure plot appearance for dark theme
        self.ax.set_facecolor(self.COLORS["surface"])  # Background area plot
        self.fig.patch.set_facecolor(self.COLORS["background"])  # Background figure

        self.ax.tick_params(
            axis="x", colors=self.COLORS["text_secondary"]
        )  # Warna tick sumbu X
        self.ax.tick_params(
            axis="y", colors=self.COLORS["text_secondary"]
        )  # Warna tick sumbu Y

        self.ax.spines["bottom"].set_color(
            self.COLORS["text_secondary"]
        )  # Warna garis sumbu
        self.ax.spines["left"].set_color(self.COLORS["text_secondary"])
        self.ax.spines["top"].set_visible(False)  # Hilangkan garis atas dan kanan
        self.ax.spines["right"].set_visible(False)

        # Add grid lines
        self.ax.grid(
            True, linestyle="--", alpha=0.3, color=self.COLORS["text_secondary"]
        )

    def _clear_status_after_delay(self, delay=3000):
        """Clear status label after specified delay in milliseconds"""
        if hasattr(self, "status_label") and self.status_label.winfo_exists():
            self.status_label.configure(text="")

    def load_and_place_background_image(self, event=None, force_reload=False):
        """Load and place background image in balance frame"""
        try:
            # Path relatif ke file gambar
            import random

            rand = random.randint(0, 1)
            if rand == 0:
                background_image_path = os.path.join("background", "hani.png")
            else:
                background_image_path = os.path.join("background", "hani2.jpg")

            if not os.path.exists(background_image_path):
                print(
                    f"[WARNING] File gambar latar belakang tidak ditemukan: {background_image_path}"
                )
                return

            # Pastikan frame saldo masih ada
            if (
                not hasattr(self, "balance_frame")
                or not self.balance_frame.winfo_exists()
            ):
                return

            frame_width = self.balance_frame.winfo_width()
            frame_height = self.balance_frame.winfo_height()

            # Tunggu sampai frame memiliki ukuran yang valid
            if frame_width <= 1 or frame_height <= 1:
                self.balance_frame.after(
                    50,
                    lambda: self.load_and_place_background_image(
                        force_reload=force_reload
                    ),
                )
                return

            # Cek apakah gambar sudah dimuat dengan ukuran yang sama dan tidak dipaksa reload
            if (
                not force_reload
                and hasattr(self, "_last_background_size")
                and self._last_background_size == (frame_width, frame_height)
            ):
                return

            # Simpan ukuran terakhir
            self._last_background_size = (frame_width, frame_height)

            # Memuat dan resize gambar
            pil_image = Image.open(background_image_path)
            resized_image = pil_image.resize(
                (frame_width, frame_height), Image.Resampling.LANCZOS
            )

            # Buat CTkImage dengan ukuran yang sesuai
            ctk_image = ctk.CTkImage(
                light_image=resized_image,
                dark_image=resized_image,
                size=(frame_width, frame_height),
            )

            # Update gambar di label latar belakang
            if (
                hasattr(self, "balance_background_label")
                and self.balance_background_label.winfo_exists()
            ):
                self.balance_background_label.configure(image=ctk_image)
                self.balance_background_label.image = ctk_image  # Keep reference

        except Exception as e:
            print(
                f"[ERROR] Gagal memuat atau menampilkan gambar latar belakang: {str(e)}"
            )


import threading


def handle_thread_exception(args):
    print(
        f"Unhandled exception in thread {args.thread.name}: {args.exc_type.__name__}: {args.exc_value}"
    )


threading.excepthook = handle_thread_exception

if __name__ == "__main__":
    app = SolanaWalletGUI()
    app.run()

