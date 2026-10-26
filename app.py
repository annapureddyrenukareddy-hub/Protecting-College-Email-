
import streamlit as st

st.set_page_config(page_title="Protecting College E-Mail", page_icon="🔐", layout="wide")
st.title("🔐 Protecting College E-Mail")
st.caption("A Cryptography and Network Security project | Unit 5: E-Mail Security")
st.write("Separate, account-protected portals let faculty send encrypted files and students receive files addressed to their own URN.")

faculty, student = st.columns(2)
with faculty:
    st.subheader("📤 Faculty Portal")
    st.write("Sign in, choose a registered student URN, and send a signed, encrypted message or attachment.")
    st.page_link("pages/1_Faculty_Portal.py", label="Open Faculty Portal", icon="📤")
with student:
    st.subheader("📥 Student Portal")
    st.write("Sign in with your account. Only messages bound to your account URN and personal encryption key can be opened.")
    st.page_link("pages/2_Student_Portal.py", label="Open Student Portal", icon="📥")

st.divider()
st.subheader("How access is checked")
st.markdown("""
1. Each student account gets its own RSA key pair. The private key is encrypted using a key derived from the student's password.
2. Faculty encrypts each message and file for the selected student's public key. The envelope carries the recipient URN, and the signed, encrypted payload carries it too.
3. The student portal checks the envelope URN against the signed-in account before decrypting, then checks the signed URN again before displaying the message or offering the file.

**Prototype note:** account registration is open for demonstration. It does not verify college identity or URN ownership, so use only for a local project demo. A deployed college service needs institution-managed enrollment, HTTPS, protected backups, and secure key recovery.
""")

with st.expander("Security concepts"):
    st.markdown("""
    - **Confidentiality:** AES-256-GCM encrypts the message and attachment; RSA-OAEP protects the AES key.
    - **Authentication and integrity:** RSA-PSS signatures verify the faculty-signed content.
    - **URN authorization:** The signed URN and account URN must match before content is shown.
    - **PGP and S/MIME:** These are related standards; this project demonstrates cryptographic building blocks and is not a complete implementation of either standard.
    """)

st.caption("Protecting College E-Mail | CNS Unit 5 | AES-GCM, RSA-OAEP, RSA-PSS, URN-bound student inbox")
