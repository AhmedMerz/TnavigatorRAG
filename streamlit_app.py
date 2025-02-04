import streamlit as st
import requests
import uuid
from supabase import create_client, Client
import os
from dotenv import load_dotenv
from datetime import datetime

# -------------------------------------------------------------------
# Load environment variables
# -------------------------------------------------------------------
load_dotenv()

# Instead of initializing WEBHOOK_URL as a constant at the top,
# we define a function that builds it dynamically.
def get_webhook_url(reasoning: bool = False) -> str:
    base_url = os.getenv("WEBHOOK_URL")  # Always read the base URL from env
    if reasoning:
        return base_url + "1"  # Append "1" if the checkbox is selected
    return base_url

# Fetch Supabase keys from environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# -------------------------------------------------------------------
# Authentication functions
# -------------------------------------------------------------------
def login(email: str, password: str):
    try:
        st.info("Attempting login ...")
        res = supabase.auth.sign_in_with_password({"email": email, "password": password})
        if res:
            st.success("Login successful.")
        return res
    except Exception as e:
        st.error(f"Login failed: {str(e)}")
        return None

def signup(email: str, password: str):
    try:
        st.info("Attempting sign up ...")
        res = supabase.auth.sign_up({"email": email, "password": password})
        if res:
            st.success("Sign up successful! You can now log in.")
        return res
    except Exception as e:
        st.error(f"Signup failed: {str(e)}")
        return None

# -------------------------------------------------------------------
# Helper / Session functions
# -------------------------------------------------------------------
def generate_session_id():
    return str(uuid.uuid4())

def init_session_state():
    if "auth" not in st.session_state:
        st.session_state.auth = None
    if "session_id" not in st.session_state:
        st.session_state.session_id = None
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "all_sessions" not in st.session_state:
        st.session_state.all_sessions = []

def load_all_sessions():
    """
    Fetch a list of all distinct session IDs (with chat_name) for the current user,
    sorted by 'timestamp' in descending order.
    """
    try:
        user_email = st.session_state.auth.user.email
        records = (
            supabase
            .table("user_conversations3")
            .select("session_id, chat_name, timestamp")
            .eq("user_email", user_email)
            .order("timestamp", desc=True)
            .execute()
        )

        if records.data:
            session_info = {}
            for row in records.data:
                sid = row["session_id"]
                if sid not in session_info:
                    session_info[sid] = {"chat_name": row["chat_name"], "timestamp": row["timestamp"]}
            def parse_timestamp(ts):
                if isinstance(ts, str):
                    try:
                        return datetime.fromisoformat(ts)
                    except Exception as e:
                        print(f"Failed to parse timestamp string '{ts}':", e)
                        return datetime.min
                return datetime.min

            sorted_sessions = sorted(
                session_info.items(),
                key=lambda x: parse_timestamp(x[1]["timestamp"]),
                reverse=True
            )
            st.session_state.all_sessions = [
                (session_id, data["chat_name"]) for session_id, data in sorted_sessions
            ]
        else:
            st.session_state.all_sessions = []
    except Exception as e:
        st.error(f"Error loading all sessions: {str(e)}")

def load_previous_messages(session_id: str):
    """
    Fetch old conversations for a given session_id and store them into st.session_state.messages
    in chronological order (oldest first).
    """
    try:
        st.session_state.messages = []
        user_email = st.session_state.auth.user.email

        records = (
            supabase
            .table("user_conversations3")
            .select("*")
            .eq("user_email", user_email)
            .eq("session_id", session_id)
            .order("timestamp", desc=True)
            .execute()
        )

        if records.data:
            for row in reversed(records.data):
                if row["question"]:
                    st.session_state.messages.append({"role": "user", "content": row["question"]})
                if row["answer"]:
                    st.session_state.messages.append({"role": "assistant", "content": row["answer"]})
        else:
            st.info("No previous messages for this session.")
    except Exception as e:
        st.error(f"Error loading previous messages: {str(e)}")

def display_chat():
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

def handle_logout():
    st.info("Logging out...")
    st.session_state.auth = None
    st.session_state.session_id = None
    st.session_state.messages = []
    if "loaded_messages" in st.session_state:
        del st.session_state["loaded_messages"]
    st.rerun()

# -------------------------------------------------------------------
# UI Components
# -------------------------------------------------------------------
def auth_ui():
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    with tab1:
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            login_res = login(email, password)
            if login_res:
                st.session_state.auth = login_res
                st.rerun()
    with tab2:
        email = st.text_input("Email", key="signup_email")
        password = st.text_input("Password", type="password", key="signup_password")
        if st.button("Sign Up"):
            signup_res = signup(email, password)
            if signup_res:
                st.success("Sign up successful! Please switch to Login tab to continue.")

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
def main():
    st.title("Tnavigator Support Agent 🤖")
    init_session_state()

    if st.session_state.auth is None:
        auth_ui()
    else:
        load_all_sessions()

        st.sidebar.success(f"Logged in as {st.session_state.auth.user.email}")

        # -------------------------------------------------------------------
        # Reasoning Checkbox in the Sidebar:
        # When checked, we use the get_webhook_url function to add "1" to the URL.
        # -------------------------------------------------------------------
        reasoning = st.sidebar.checkbox("Reasoning")
        final_webhook_url = get_webhook_url(reasoning)

        # Sidebar session management
        if st.session_state.all_sessions:
            session_ids = [s[0] for s in st.session_state.all_sessions]
            def session_format_func(sid):
                for stored_sid, chat_name in st.session_state.all_sessions:
                    if stored_sid == sid:
                        return chat_name if chat_name else f"(No Name) - {sid[:6]}"
                return "Unknown Session"

            if st.session_state.session_id in session_ids:
                current_index = session_ids.index(st.session_state.session_id)
            else:
                current_index = 0

            selected_session = st.sidebar.selectbox(
                "Pick a session",
                options=session_ids,
                index=current_index,
                format_func=session_format_func
            )
        else:
            st.sidebar.write("No sessions found. Create a new one below.")
            selected_session = None

        if st.sidebar.button("Load Selected Session"):
            if selected_session:
                st.session_state.session_id = selected_session
                load_previous_messages(st.session_state.session_id)
                st.rerun()
            else:
                st.warning("No session selected to load.")

        if st.sidebar.button("Start New Session"):
            new_id = generate_session_id()
            st.session_state.session_id = new_id
            st.session_state.messages = []
            st.rerun()

        if st.sidebar.button("Logout"):
            handle_logout()

        # Display the chat for the current session
        display_chat()

        # Chat input
        if st.session_state.session_id is not None:
            prompt = st.chat_input("What is your message?")
            if prompt:
                st.session_state.messages.append({"role": "user", "content": prompt})
                with st.chat_message("user"):
                    st.markdown(prompt)

                payload = {
                    "chatInput": prompt,
                    "sessionId": st.session_state.session_id
                }

                # Get the access token from the session
                access_token = st.session_state.auth.session.access_token
                headers = {
                    "Authorization": f"Bearer {access_token}"
                }

                with st.spinner("AI is thinking..."):
                    response = requests.post(final_webhook_url, json=payload, headers=headers)
                if response.status_code == 200:
                    try:
                        resp_json = response.json()
                        if isinstance(resp_json, list) and resp_json:
                            first_item = resp_json[0]
                            if isinstance(first_item, dict) and "data" in first_item:
                                data_list = first_item["data"]
                                if isinstance(data_list, list) and data_list:
                                    ai_message = data_list[0].get("output ", "No 'output' key found.")
                                    st.session_state.messages.append({"role": "assistant", "content": ai_message})
                                    with st.chat_message("assistant"):
                                        st.markdown(ai_message)
                                        st.markdown("---")
                                        st.markdown("### Related Tutorials:")
                                        tutorials_container = st.container()
                                        cols = tutorials_container.columns(2)
                                        for idx, tutorial in enumerate(data_list[1:]):
                                            if 'titleSlide' in tutorial and 'Link' in tutorial:
                                                col = cols[idx % 2]
                                                with col:
                                                    st.markdown(f"📚 **[{tutorial['titleSlide']}]({tutorial['Link']})**")
                    except ValueError:
                        st.error("Response is not valid JSON.")
                else:
                    st.error(f"Error: {response.status_code} - {response.text}")

if __name__ == "__main__":
    main()
