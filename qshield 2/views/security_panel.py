"""Show accurate capabilities for the integrated demo."""
import streamlit as st
from core.security_status import get_feature_list


def show_security_status() -> None:
    st.header('🛡️ Security Status')
    st.info('Prototype: local encrypted-package creation and decryption are connected. This is not an audited product.')
    st.table(get_feature_list())
    st.warning('Sender identity verification and network delivery are not implemented. Use test files only.')
