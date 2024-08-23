import streamlit as st
import pandas as pd
from EDA_functions import pcap_to_csv
from ydata_profiling import ProfileReport
import tempfile
import streamlit.components.v1 as components
from Models_functions import input_page
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

                # Create and save the profile report to a temporary file
                st.write("Generating Profile Report...")
                pr = ProfileReport(df, explorative=True)
                                # Save report to a temporary file
                with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
                    pr.to_file(tmp_file.name)
                    tmp_file.seek(0)
                    st.download_button(
                        label="Download Report",
                        data=tmp_file.read(),
                        file_name="profile_report.html",
                        mime="text/html"
                    )

                # Save report to a temporary file
                with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
                    pr.to_file(tmp_file.name)
                    tmp_file.seek(0)
                    report_html = tmp_file.read().decode()

                # Display the profile report
                components.html(report_html, height=800)

                # Provide a download link for the dataset
                st.write("Download the dataset:")
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download Dataset",
                    data=csv,
                    file_name="dataset.csv",
                    mime="text/csv"
                )

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
if st.sidebar.button('Input'):
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
    st.title("Input")
    st.write("This app allows you to upload a PCAP file, convert it to a CSV, and generate a profiling report.")

    input_page()
