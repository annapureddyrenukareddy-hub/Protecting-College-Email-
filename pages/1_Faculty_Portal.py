import json

import streamlit as st

from crypto_utils import create_secure_email
from portal_store import (
    add_mail,
    authenticate,
    list_students,
    register_user,
)

st.set_page_config(page_title="Faculty Portal | College E-Mail", page_icon="📤", layout="wide")
st.title("📤 Faculty Portal")
st.caption("Compose and send signed, URN-bound encrypted email and files.")

if "portal_user" not in st.session_state:
    st.session_state.portal_user = None
    st.session_state.student_private_key = None


def show_auth():
    login_tab, signup_tab = st.tabs(["Sign in", "Create faculty account"])
    with login_tab:
        with st.form("faculty_login"):
            username = st.text_input("Username", key="faculty_login_username")
            password = st.text_input("Password", type="password", key="faculty_login_password")
            submitted = st.form_submit_button("Sign in", type="primary")
        if submitted:
            user, _private_key = authenticate(username, password)
            if user and user["role"] == "faculty":
                st.session_state.portal_user = user
                st.session_state.student_private_key = None
                st.rerun()
            st.error("Sign-in failed. Check your username, password, and account type.")
    with signup_tab:
        st.info("Faculty accounts are for this local project demonstration. Registration does not verify college employment.")
        with st.form("faculty_signup"):
            display_name = st.text_input("Faculty name", key="faculty_signup_name")
            username = st.text_input("Choose a username", key="faculty_signup_username")
            password = st.text_input("Choose a password", type="password", key="faculty_signup_password")
            confirm = st.text_input("Confirm password", type="password", key="faculty_signup_confirm")
            submitted = st.form_submit_button("Create faculty account")
        if submitted:
            if password != confirm:
                st.error("The passwords do not match.")
            else:
                try:
                    register_user(username, password, "faculty", display_name=display_name)
                    st.success("Account created. Sign in to continue.")
                except ValueError as error:
                    st.error(str(error))

user = st.session_state.portal_user
if not user or user.get("role") != "faculty":
    show_auth()
    st.stop()

st.write(f"Signed in as **{user['display_name']}**")
if st.button("Sign out", key="faculty_sign_out"):
    st.session_state.portal_user = None
    st.session_state.student_private_key = None
    st.rerun()

students = list_students()
if not students:
    st.warning("No student accounts exist yet. Ask the student to create an account in the Student Portal, then return here.")
    st.stop()

student_options = {f"{s['urn']} — {s['display_name']}": s for s in students}
with st.form("faculty_send_form"):
    recipient_label = st.selectbox("Student URN", list(student_options))
    subject = st.text_input("Subject", value="Important College Document")
    message = st.text_area("Message", placeholder="Enter a confidential message…", height=150)
    attachment = st.file_uploader("Attach a file (optional)")
    submitted = st.form_submit_button("🔒 Encrypt and send", type="primary")

if submitted:
    recipient = student_options[recipient_label]
    if not subject.strip():
        st.error("Enter a subject.")
    elif not message.strip() and attachment is None:
        st.error("Enter a message or attach a file.")
    else:
        try:
            details = {
                "sender": user["display_name"],
                "recipient": recipient["urn"],
                "subject": subject.strip(),
                "message": message,
            }
            envelope = create_secure_email(
                message=json.dumps(details, ensure_ascii=False, sort_keys=True),
                attachment_name=attachment.name if attachment else None,
                attachment_data=attachment.getvalue() if attachment else None,
                recipient_urn=recipient["urn"],
                recipient_public_key=recipient["public_key"],
            )
            mail_id = add_mail(user["username"], recipient["urn"], envelope)
            st.success(f"Encrypted message sent to URN {recipient['urn']}.")
            st.caption("A fresh AES-256 key was generated for this message and encrypted to the student's account key. The message and file are stored as an encrypted envelope.")
            st.download_button(
                "Download encrypted envelope",
                data=json.dumps(envelope, indent=2).encode("utf-8"),
                file_name=f"secure_email_{mail_id[:8]}.json",
                mime="application/json",
            )
            with st.expander("Envelope (ciphertext and routing URN only)"):
                st.json({k: v for k, v in envelope.items() if k != "ciphertext"})
        except Exception as error:
            st.error(f"Could not send the encrypted message: {error}")

st.divider()
st.subheader("Encryption details")
col1, col2 = st.columns(2)
col1.metric("Content encryption", "AES-256-GCM")
col1.metric("Student key", "RSA-OAEP-SHA256")
col2.metric("Faculty signature", "RSA-PSS-SHA256")
col2.metric("URN authorization", "Required")

