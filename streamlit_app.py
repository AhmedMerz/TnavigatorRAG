import streamlit as st
import requests
import uuid

import os
import subprocess

# Install the required library if not found
try:
    from supabase import create_client, Client
except ModuleNotFoundError:
    print("Installing missing libraries...")
    subprocess.check_call(["pip", "install", "supabase"])
    from supabase import create_client, Client
from supabase import create_client, Client

# Supabase setup
SUPABASE_URL = "https://czhtrajjirbzyjijbntr.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImN6aHRyYWpqaXJienlqaWpibnRyIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTczNDEwMDUxMCwiZXhwIjoyMDQ5Njc2NTEwfQ._5MCB4psUSFTTYbNRGvuGxb_q9ZYsZYoBrp769CG2Vk"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Webhook URL (replace with your n8n webhook URL)
WEBHOOK_URL = "https://ahmedmerzoug.app.n8n.cloud/webhook/invokeTnavRAG"

def login(email: str, password: str):
    try:
        res = supabase.auth.sign_in_with_password({"email": email, "password": password})
        return res
    except Exception as e:
        st.error(f"Login failed: {str(e)}")
        return None

def signup(email: str, password: str):
    try:
        res = supabase.auth.sign_up({"email": email, "password": password})
        return res
    except Exception as e:
        st.error(f"Signup failed: {str(e)}")
        return None

def generate_session_id():
    return str(uuid.uuid4())

def init_session_state():
    if "auth" not in st.session_state:
        st.session_state.auth = None
    if "session_id" not in st.session_state:
        st.session_state.session_id = None
    if "messages" not in st.session_state:
        st.session_state.messages = []

def display_chat():
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

def handle_logout():
    st.session_state.auth = None
    st.session_state.session_id = None
    st.session_state.messages = []
    st.rerun()

def auth_ui():
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            auth = login(email, password)
            if auth:
                st.session_state.auth = auth
                st.session_state.session_id = generate_session_id()
                st.rerun()

    with tab2:
        email = st.text_input("Email", key="signup_email")
        password = st.text_input("Password", type="password", key="signup_password")
        if st.button("Sign Up"):
            auth = signup(email, password)
            if auth:
                st.success("Sign up successful! Please log in.")

def main():
    st.title("Tnavigator Support Agent 🤖")
    init_session_state()

    if st.session_state.auth is None:
        auth_ui()
    else:
        st.sidebar.success(f"Logged in as {st.session_state.auth.user.email}")
        st.sidebar.info(f"Session ID: {st.session_state.session_id}")

        if st.sidebar.button("Logout"):
            handle_logout()

        display_chat()

        if prompt := st.chat_input("What is your message?"):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            # Prepare the payload
            payload = {
                "chatInput": prompt,
                "sessionId": st.session_state.session_id
            }
            
            # Get the access token from the session
            access_token = st.session_state.auth.session.access_token
            
            # Send request to webhook
            headers = {
                "Authorization": f"Bearer {access_token}"
            }
            with st.spinner("AI is thinking..."):
                response = requests.post(WEBHOOK_URL, json=payload, headers=headers)
            
            if response.status_code == 200:
                try:
                    response_json = response.json()
                    # Debug: Display parsed JSON


                    # Adjusting to handle the list response
                    if isinstance(response_json, list) and len(response_json) > 0:
                        first_item = response_json[0]

                        # Access the key with trailing space
                        ai_message = first_item.get("output ", "Sorry, I couldn't generate a response.")
                    elif isinstance(response_json, dict):
                        ai_message = response_json.get("output", "Sorry, I couldn't generate a response.")
                    else:
                        ai_message = "Sorry, I couldn't generate a response."

                except Exception as e:
                    st.error(f"Error parsing JSON: {e}")
                    st.write("Response Text:", response.text)
                    ai_message = "Sorry, I couldn't generate a response."


                st.session_state.messages.append({"role": "assistant", "content": ai_message})
                with st.chat_message("assistant"):
                    st.markdown(ai_message)
            else:
                st.error(f"Error: {response.status_code} - {response.text}")

if __name__ == "__main__":
    main()
