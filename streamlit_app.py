import streamlit as st
import requests
import uuid
from supabase import create_client, Client
import os
from dotenv import load_dotenv
from datetime import datetime

# -------------------------------------------------------------------
# Supabase configuration
# -------------------------------------------------------------------
# Load environment variables from .env file
load_dotenv()

# Fetch keys securely
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")

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
        # Fetch session_id, chat_name, timestamp
        records = (
            supabase
            .table("user_conversations3")
            .select("session_id, chat_name, timestamp")
            .eq("user_email", user_email)
            .order("timestamp", desc=True)
            .execute()
        )

        if records.data:
            # We'll collect data in a dict keyed by session_id
            session_info = {}
            for row in records.data:
                sid = row["session_id"]
                # Only record the first chat_name we see per sid
                if sid not in session_info:
                    # Let chat_name be exactly what's in the DB (can be None or empty)
                    chat_name = row["chat_name"]
                    session_info[sid] = {
                        "chat_name": chat_name,
                        "timestamp": row["timestamp"],
                    }

            # Sort by timestamp DESC
            sorted_sessions = sorted(
                session_info.items(),
                key=lambda x: x[1]["timestamp"],
                reverse=True
            )

            # Convert to a list of (session_id, chat_name)
            st.session_state.all_sessions = [
                (session_id, data["chat_name"]) for session_id, data in sorted_sessions
            ]
        else:
            st.session_state.all_sessions = []
    except Exception as e:
        st.error(f"Error loading all sessions: {str(e)}")

def load_previous_messages(session_id: str):
    """
    Fetch old conversations for a given session_id and
    store them into st.session_state.messages in chronological order (oldest first).
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
                # If there's no question/answer, it might just be a placeholder row
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

        # If there are existing sessions, let the user pick one
        if st.session_state.all_sessions:
            # Gather session_ids
            session_ids = [s[0] for s in st.session_state.all_sessions]

            # Helper to map session_id -> chat_name
            def session_format_func(sid):
                for stored_sid, chat_name in st.session_state.all_sessions:
                    if stored_sid == sid:
                        # If there's no chat_name, fallback to session_id or blank
                        return chat_name if chat_name else f"(No Name) - {sid[:6]}"
                return "Unknown Session"

            # Determine the current index if it exists
            if st.session_state.session_id in session_ids:
                current_index = session_ids.index(st.session_state.session_id)
            else:
                current_index = 0

            selected_session = st.sidebar.selectbox(
                "Pick a session (descending order by time)",
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
            # Only set session state, no DB insertion; naming is handled by the webhook
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
                    response = requests.post(WEBHOOK_URL, json=payload, headers=headers)
                if response.status_code == 200:
                    try:
                        resp_json = response.json()
                        
                        if isinstance(resp_json, list) and resp_json:
                            first_item = resp_json[0]  # Get first item in the list
                            
                            if isinstance(first_item, dict) and "data" in first_item:
                                data_list = first_item["data"]
                                
                                if isinstance(data_list, list) and data_list:
                                    # Get the AI message
                                    ai_message = data_list[0].get("output ", "No 'output' key found.")
                                    
                                    # Display the AI message
                                    st.session_state.messages.append({"role": "assistant", "content": ai_message})
                                    with st.chat_message("assistant"):
                                        st.markdown(ai_message)
                                        
                                        # Add a separator and heading for tutorials
                                       # Add a separator and heading for tutorials
                                        st.markdown("---")
                                        st.markdown("### Related Tutorials:")
                                        
                                        # Create a container for the tutorial links
                                        tutorials_container = st.container()
                                        
                                        # Optionally, use columns for better layout
                                        cols = tutorials_container.columns(2)  # Adjust the number based on preference
                                        
                                        for idx, tutorial in enumerate(data_list[1:]):
                                            if 'titleSlide' in tutorial and 'Link' in tutorial:
                                                col = cols[idx % 2]  # Distribute tutorials across columns
                                                with col:
                                                    # Using Markdown with icons for better visuals
                                                    st.markdown(f"📚 **[{tutorial['titleSlide']}]({tutorial['Link']})**")


                    except ValueError:
                        ai_message = "Response is not valid JSON."
                else:
                    ai_message = f"Error: {response.status_code} - {response.text}"

if __name__ == "__main__":
    main()
