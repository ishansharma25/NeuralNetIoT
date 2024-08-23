import streamlit as st
import pandas as pd
from EDA_functions import pcap_to_csv
from ydata_profiling import ProfileReport
from Models_functions import input_page
from streamlit_pandas_profiling import st_profile_report

# Initialize session state for navigation
if 'page' not in st.session_state:
    st.session_state.page = 'home'

def load_csv():
    uploaded_pcap = st.file_uploader("Choose a PCAP file")
    
    if uploaded_pcap is not None:
        st.write("File uploaded successfully")
        st.write(f"File name: {uploaded_pcap.name}")
        st.write(f"File type: {uploaded_pcap.type}")
        st.write(f"File size: {uploaded_pcap.size} bytes")
        
        try:
            df = pcap_to_csv(uploaded_pcap)
            if df is not None and not df.empty:
                st.write("DataFrame created successfully")
                st.write(f"DataFrame shape: {df.shape}")
                
                # Create and display the profile report
                st.write("Generating Profile Report...")
                pr = ProfileReport(df, explorative=True)
                st_profile_report(pr)
                
                return df
            else:
                st.warning("The created DataFrame is empty.")
                return None
        except Exception as e:
            st.error(f"Error processing PCAP file: {str(e)}")
            return None
    else:
        st.warning("Please upload a PCAP file.")
    return None

# Navigation buttons
if st.sidebar.button('Home'):
    st.session_state.page = 'home'
if st.sidebar.button('input'):
    st.session_state.page = 'input'

# Display content based on the selected page
if st.session_state.page == 'home':
    st.title("PCAP File Analyzer")
    df = load_csv()
    if df is not None:
        st.write("Raw DataFrame:")
        st.write(df)
    else:
        st.write("No data to display.")
elif st.session_state.page == 'input':
    st.title("input")
    st.write("This app allows you to upload a PCAP file, convert it to a CSV, and generate a profiling report.")
    
    input_page()

    