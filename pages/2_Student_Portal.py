import json
import streamlit as st

from crypto_utils import receive_secure_email
from portal_store import (
    authenticate,
    list_mail_for_urn,
    register_user,
    urn_key,
)

st.set_page_config(page_title="Student Portal | College E-Mail", page_icon="📥", layout="wide")
st.title("📥 Student Portal")
st.caption("Your inbox is tied to your account URN and personal encryption key.")

if "portal_user" not in st.session_state:
    st.session_state.portal_user = None
if "student_private_key" not in st.session_state:
    st.session_state.student_private_key = None


def show_auth():
    login_tab, signup_tab = st.tabs(["Sign in", "Create student account"])
    with login_tab:
        with st.form("student_login"):
            username = st.text_input("Username", key="student_login_username")
            password = st.text_input("Password", type="password", key="student_login_password")
            submitted = st.form_submit_button("Sign in", type="primary")
        if submitted:
            user, private_key = authenticate(username, password)
            if user and user["role"] == "student":
                st.session_state.portal_user = user
                st.session_state.student_private_key = private_key
                st.rerun()
            st.error("Sign-in failed. Check your username, password, and account type.")
    with signup_tab:
        st.info("Create a demo account with your URN. The app does not verify URN ownership; use only for a local project demonstration.")
        with st.form("student_signup"):
            display_name = st.text_input("Student name", key="student_signup_name")
            urn = st.text_input("Student URN", key="student_signup_urn")
            username = st.text_input("Choose a username", key="student_signup_username")
            password = st.text_input("Choose a password", type="password", key="student_signup_password")
            confirm = st.text_input("Confirm password", type="password", key="student_signup_confirm")
            submitted = st.form_submit_button("Create student account")
        if submitted:
            if password != confirm:
                st.error("The passwords do not match.")
            else:
                try:
                    register_user(username, password, "student", display_name=display_name, urn=urn)
                    st.success("Student account and personal encryption key created. Sign in to open your inbox.")
                except ValueError as error:
                    st.error(str(error))

user = st.session_state.portal_user
if not user or user.get("role") != "student":
    show_auth()
    st.stop()

st.write(f"Signed in as **{user['display_name']}** · URN **{user['urn']}**")
if st.button("Sign out", key="student_sign_out"):
    st.session_state.portal_user = None
    st.session_state.student_private_key = None
    st.rerun()

mail = list_mail_for_urn(user["urn"])
st.subheader("Your encrypted inbox")
if not mail:
    st.info("No encrypted messages have been sent to your URN yet.")
    st.stop()

labels = [f"{row['created_at']} · From {row['sender_username']} · Message {row['id'][:8]}" for row in mail]
selected_index = st.selectbox("Choose a message", range(len(mail)), format_func=lambda i: labels[i])
selected = mail[selected_index]

if st.button("🔓 Verify URN and decrypt", type="primary"):
    try:
        # The envelope URN is checked before private-key decryption. The signed payload URN is checked again inside receive_secure_email.
        payload = receive_secure_email(
            selected["envelope"],
            student_private_key=st.session_state.student_private_key,
            expected_urn=user["urn"],
        )
        details = json.loads(payload["message"])
        if urn_key(details.get("recipient", "")) != urn_key(user["urn"]):
            raise ValueError("The signed message recipient does not match the logged-in student.")
        st.success("URN matched. Decryption succeeded and the faculty signature was verified.")
        st.subheader(details.get("subject", "Verified message"))
        st.write(f"**From:** {details.get('sender', 'Faculty')}")
        st.write(f"**To:** {details.get('recipient', '')}")
        st.markdown("**Message**")
        st.text(details.get("message", ""))
        if payload.get("attachment_data") is not None:
            st.divider()
            st.subheader("Verified file")
            st.write(payload.get("attachment_name") or "attachment")
            st.download_button(
                "Download decrypted file",
                data=payload["attachment_data"],
                file_name=payload.get("attachment_name") or "attachment",
                mime="application/octet-stream",
            )
        st.caption("Only this student's account key can decrypt the envelope. The URN comparison is also enforced before showing the signed message or file.")
    except Exception:
        st.error("Access denied. The logged-in URN does not match the message, or the file could not be decrypted and verified.")
