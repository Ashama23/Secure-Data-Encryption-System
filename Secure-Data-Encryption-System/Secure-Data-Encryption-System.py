import streamlit as st
import hashlib
from cryptography.fernet import Fernet

if 'key' not in st.session_state:
    st.session_state.key = Fernet.generate_key()

cipher = Fernet(st.session_state.key)

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'page' not in st.session_state:
    st.session_state.page = "Home"


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode())

def decrypt_data(encrypted_bytes):
    return cipher.decrypt(encrypted_bytes).decode()

st.set_page_config(page_title="Secure Vault", layout="centered")
st.title("🔒 Secure Data Encryption System")

st.sidebar.title("Navigation")
if st.sidebar.button("🏠 Home", use_container_width=True):
    st.session_state.page = "Home"
if st.sidebar.button("📂 Store Data", use_container_width=True):
    st.session_state.page = "Store Data"
if st.sidebar.button("🔍 Retrieve Data", use_container_width=True):
    st.session_state.page = "Retrieve Data"
    st.session_state.failed_attempts = 0

if st.session_state.page == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.info("Your data is stored in memory and will be erased when the app is closed.", icon="ℹ️")

elif st.session_state.page == "Store Data":
    st.subheader("📂 Store New Data Securely")
    
    with st.form("store_form"):
        user_data = st.text_area("Enter Text to Encrypt:")
        passkey = st.text_input("Create a Passkey:", type="password")
        submitted = st.form_submit_button("Encrypt & Store")

        if submitted:
            if user_data and passkey:
                data_id = hashlib.md5(user_data.encode()).hexdigest()
                
                if data_id in st.session_state.stored_data:
                    st.warning("This exact data has already been stored.", icon="⚠️")
                else:
                    encrypted_text = encrypt_data(user_data)
                    passkey_hash = hash_passkey(passkey)
                    st.session_state.stored_data[data_id] = {
                        "encrypted_text": encrypted_text,
                        "passkey_hash": passkey_hash
                    }
                    st.success("Data stored securely!", icon="✅")
                    st.code(data_id, language="text")
                    st.info("This is your unique Data ID. You will need it to retrieve your data.", icon="ℹ️")
            else:
                st.error("Both data and passkey fields are required.", icon="❌")

elif st.session_state.page == "Retrieve Data":
    if st.session_state.failed_attempts >= 3:
        st.subheader("🔑 Reauthorization Required")
        st.error("Too many failed attempts. Please reauthorize.", icon="🔒")
        
        with st.form("login_form"):
            master_pass = st.text_input("Enter Master Password:", type="password")
            login_submitted = st.form_submit_button("Login")
            
            if login_submitted:
                if master_pass == "admin123":
                    st.session_state.failed_attempts = 0
                    st.success("Reauthorized successfully! You can now try again.", icon="✅")
                    st.experimental_rerun()
                else:
                    st.error("Incorrect master password.", icon="❌")
    else:
        st.subheader("🔍 Retrieve Your Data")
        
        with st.form("retrieve_form"):
            data_id = st.text_input("Enter Your Data ID:")
            passkey = st.text_input("Enter Your Passkey:", type="password")
            retrieve_submitted = st.form_submit_button("Decrypt Data")

            if retrieve_submitted:
                if data_id and passkey:
                    if data_id in st.session_state.stored_data:
                        stored_info = st.session_state.stored_data[data_id]
                        passkey_hash_attempt = hash_passkey(passkey)
                
                        if passkey_hash_attempt == stored_info["passkey_hash"]:
                            decrypted_text = decrypt_data(stored_info["encrypted_text"])
                            st.success("Decryption Successful!", icon="✅")
                            st.text_area("Your Decrypted Data:", value=decrypted_text, height=150)
                            st.session_state.failed_attempts = 0 
                        else:
                            st.session_state.failed_attempts += 1
                            remaining_attempts = 3 - st.session_state.failed_attempts
                            st.error(f"Incorrect Passkey! Attempts remaining: {remaining_attempts}", icon="❌")
                            if st.session_state.failed_attempts >= 3:
                                st.experimental_rerun()
                    else:
                        st.error("Data ID not found.", icon="❌")
                else:
                    st.error("Both Data ID and Passkey are required.", icon="❌")