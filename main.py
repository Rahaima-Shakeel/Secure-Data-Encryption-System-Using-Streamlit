# This is a Streamlit-based Python application designed to securely store and retrieve private text data using encryption and passkey authentication.
# -------------------- IMPORTS --------------------
# Streamlit is used to build interactive web apps easily
import streamlit as st

# hashlib is used to hash the passkey (so we never store actual passwords)
import hashlib

# Fernet from cryptography provides symmetric encryption and decryption
from cryptography.fernet import Fernet


# -------------------- APP CONFIGURATION --------------------
# Set title, icon, and layout of the Streamlit app
st.set_page_config(page_title="🔐 Secure Storage", page_icon="🛡️", layout="centered")

# Display a centered title using HTML
st.markdown("<h1 style='text-align:center;'>🛡️ Secure Data Vault</h1>", unsafe_allow_html=True)


# -------------------- SESSION STATE VARIABLES --------------------
# Generate encryption key and cipher once per session
if "key" not in st.session_state:
    st.session_state.key = Fernet.generate_key()  # Creates a unique encryption key
    st.session_state.cipher = Fernet(st.session_state.key)  # Fernet object for encrypt/decrypt

# Initialize empty list to store data entries
if "stored_data" not in st.session_state:
    st.session_state.stored_data = []

# Track failed login attempts for security
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Track whether the user is currently authenticated
if "authenticated" not in st.session_state:
    st.session_state.authenticated = True  # Starts as True; becomes False after 3 wrong attempts


# -------------------- UTILITY FUNCTIONS --------------------
# Convert passkey to a secure hash (so we don’t store the actual passkey)
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt user text using Fernet cipher
def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

# Decrypt encrypted text back to readable form
def decrypt_data(encrypted_text):
    return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()


# -------------------- PAGE FUNCTIONS --------------------
# HOME PAGE
def home():
    st.info("Choose an option from the sidebar to begin!")
    st.markdown("🔐 **This app securely stores and retrieves your private data using strong encryption and passkeys.**")

# STORE DATA PAGE
def store_page():
    st.subheader("📥 Store Encrypted Data")
    
    # Input fields from the user
    label = st.text_input("Enter a label for this data (e.g., 'My Notes'):")
    user_data = st.text_area("Enter the data you want to encrypt:")
    passkey = st.text_input("Set a secret passkey:", type="password")

    # Button to trigger encryption
    if st.button("🔒 Encrypt & Save"):
        if label and user_data and passkey:
            encrypted = encrypt_data(user_data)  # Encrypt the data
            hashed = hash_passkey(passkey)       # Hash the passkey

            # Save encrypted data with label and hashed passkey
            st.session_state.stored_data.append({
                "label": label,
                "encrypted_text": encrypted,
                "passkey": hashed
            })
            st.success("✅ Data stored securely!")
        else:
            st.error("❗ Please fill out all fields.")

# RETRIEVE DATA PAGE
def retrieve_page():
    # If user is not authenticated, ask them to log in
    if not st.session_state.authenticated:
        login_page()
        return

    st.subheader("🔓 Retrieve Encrypted Data")

    # If no data has been stored yet
    if not st.session_state.stored_data:
        st.warning("⚠️ No data stored yet.")
        return

    # Let user select label of stored data
    labels = [entry["label"] for entry in st.session_state.stored_data]
    selected_label = st.selectbox("Select the data to retrieve:", labels)

    # Ask user for the passkey to decrypt the data
    passkey = st.text_input("Enter your passkey:", type="password")

    # Button to trigger decryption
    if st.button("🔍 Decrypt"):
        for entry in st.session_state.stored_data:
            if entry["label"] == selected_label:
                if hash_passkey(passkey) == entry["passkey"]:
                    # Correct passkey — decrypt and show data
                    st.success(f"✅ Decrypted Data: {decrypt_data(entry['encrypted_text'])}")
                    st.session_state.failed_attempts = 0  # Reset failed attempts
                    return
                else:
                    # Incorrect passkey
                    st.session_state.failed_attempts += 1
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")

                    # Lock out after 3 failed attempts
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.authenticated = False
                        st.warning("🔐 Too many failed attempts. Login required.")
                        st.experimental_rerun()
                    return

# LOGIN PAGE (for unlocking after 3 failed attempts)
def login_page():
    st.subheader("🔐 Reauthorize Access")
    login = st.text_input("Enter Admin Password:", type="password")

    if st.button("🔑 Login"):
        if login == "admin123":  # Hardcoded admin password (can be improved later)
            st.success("✅ Reauthorized successfully.")
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password.")


# -------------------- SIDEBAR NAVIGATION --------------------
# Create a navigation menu on the left sidebar
menu = ["Home", "Store Data", "Retrieve Data"]
if not st.session_state.authenticated:
    menu.append("Login")
choice = st.sidebar.radio("Navigation", menu)


# -------------------- PAGE ROUTING --------------------
# Call the correct page function based on user’s choice
if choice == "Home":
    home()
elif choice == "Store Data":
    store_page()
elif choice == "Retrieve Data":
    retrieve_page()
elif choice == "Login":
    login_page()