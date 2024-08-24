import os
import tensorflow as tf
import tensorflow_hub as hub
from tensorflow.keras.models import load_model
import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import struct
import socket
import ipaddress
from tensorflow.keras.layers import GRU, LSTM
from tensorflow.keras.initializers import Orthogonal
import shap
import traceback

def input_page():
    # Suppress TensorFlow warnings (optional)
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Suppresses INFO and WARNING messages

    # Set environment variable to disable oneDNN custom operations (optional)
    os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

    def load_selected_model(model_name):
        try:
            # Custom LSTM layer to handle the 'time_major' argument
            class CustomLSTM(LSTM):
                def __init__(self, *args, **kwargs):
                    kwargs.pop('time_major', None)  # Remove 'time_major' if present
                    kwargs.pop('implementation', None)  # Remove 'implementation' if present
                    super().__init__(*args, **kwargs)

            # Custom GRU layer to handle the 'time_major' and 'implementation' arguments
            class CustomGRU(GRU):
                def __init__(self, *args, **kwargs):
                    kwargs.pop('time_major', None)  # Remove 'time_major' if present
                    kwargs.pop('implementation', None)  # Remove 'implementation' if present
                    super().__init__(*args, **kwargs)

            # Custom objects dictionary
            custom_objects = {
                'KerasLayer': hub.KerasLayer,
                'Orthogonal': Orthogonal,
                'LSTM': CustomLSTM,
                'GRU': CustomGRU
            }

            # Load the model with custom objects
            model = load_model(model_name, custom_objects=custom_objects)
            
            #st.write("Model Architecture:")
            #model.summary(print_fn=lambda x: st.write(x))
            
            return model
        except Exception as e:
            st.error(f"Error loading model: {str(e)}")
            return None

    def process_time(time):
        time = time.split(" ")[-1]
        h, m = time.split(":")
        return 3600*int(h)+60*int(m)

    def flags_transform(flags):
        value = 0
        if type(flags) is str:
            flags = flags.replace(" ", "")
            for c in flags:
                if c != ',':
                    value += ord(c)
        return value



    def preprocess_data(data):
        def process_ip(ip):
            try:
                return int(ipaddress.ip_address(ip))
            except ValueError:
                st.warning(f"Invalid IP address: {ip}. Using 0 instead.")
                return 0

        data["source"] = data["source"].apply(process_ip)
        data["destination"] = data["destination"].apply(process_ip)
        
        data["startDateTime"] = data["startDateTime"].apply(
            lambda time: process_time(time)
        )
        data["stopDateTime"] = data["stopDateTime"].apply(
            lambda time: process_time(time)
        )
        data["sourceTCPFlagsDescription"] = data["sourceTCPFlagsDescription"].apply(
            lambda flags: flags_transform(flags)
        )
        data["destinationTCPFlagsDescription"] = data["destinationTCPFlagsDescription"].apply(
            lambda flags: flags_transform(flags)
        )
        data["protocolName"] = data["protocolName"].astype("category")
        data["protocolName"] = data["protocolName"].cat.codes
        data["appName"] = data["appName"].astype("category")
        data["appName"] = data["appName"].cat.codes
        data["direction"] = data["direction"].astype("category")
        data["direction"] = data["direction"].cat.codes
        data = data.fillna(0)
        
        # Add custom attack indicators
        data['high_byte_ratio'] = data['totalSourceBytes'] / (data['totalDestinationBytes'] + 1)
        data['suspicious_port'] = ((data['sourcePort'] == 31337) | (data['destinationPort'] == 31337)).astype(int)
        data['urg_flag'] = data['sourceTCPFlagsDescription'].apply(lambda x: 'URG' in str(x)).astype(int)
        
        return data

    def validate_input(input_data):
        if input_data['totalSourceBytes'] < 0 or input_data['totalDestinationBytes'] < 0:
            return False, "Bytes cannot be negative"
        if input_data['totalSourcePackets'] < 0 or input_data['totalDestinationPackets'] < 0:
            return False, "Packets cannot be negative"
        if input_data['sourcePort'] < 0 or input_data['sourcePort'] > 65535:
            return False, "Invalid source port"
        if input_data['destinationPort'] < 0 or input_data['destinationPort'] > 65535:
            return False, "Invalid destination port"
        return True, ""

    def plot_feature_importance(model, data):
        explainer = shap.DeepExplainer(model, data)
        shap_values = explainer.shap_values(data)
        
        plt.figure(figsize=(10, 6))
        shap.summary_plot(shap_values[0], data, plot_type="bar", show=False)
        st.pyplot(plt)

    def predict_traffic(model, data, threshold=0.3):
        prediction = model.predict(data)
        raw_prediction = prediction[0][0]
        
        # Custom rule checks
        if isinstance(data, pd.DataFrame):
            high_byte_ratio = data['high_byte_ratio'].iloc[0]
            suspicious_port = data['suspicious_port'].iloc[0]
            urg_flag = data['urg_flag'].iloc[0]
            
            st.write(f"High byte ratio: {high_byte_ratio}")
            st.write(f"Suspicious port: {suspicious_port}")
            st.write(f"URG flag: {urg_flag}")
            
            if (high_byte_ratio > 1000 or suspicious_port == 1):
                st.write("Custom rule triggered: Attack detected")
                return "Attack", raw_prediction
        elif isinstance(data, np.ndarray):
            high_byte_ratio_index = -3  # Third to last column
            suspicious_port_index = -2  # Second to last column
            urg_flag_index = -1  # Last column
            if (data[0, high_byte_ratio_index] > 1000 and 
                data[0, suspicious_port_index] == 1 and 
                data[0, urg_flag_index] == 1):
                st.write("Custom rule triggered: Attack detected")
                return "Attack", raw_prediction
        
        return "Attack" if raw_prediction > threshold else "Normal", raw_prediction

    def generate_attack_data():
        return pd.DataFrame({
            'appName': ['Unknown_TCP'],
            'totalSourceBytes': [1000000],
            'totalDestinationBytes': [500],
            'totalDestinationPackets': [5],
            'totalSourcePackets': [1000],
            'direction': ['L2R'],
            'sourceTCPFlagsDescription': ['SYN,ACK,PSH,URG'],
            'destinationTCPFlagsDescription': ['ACK'],
            'source': ['192.168.1.100'],
            'protocolName': ['tcp_ip'],
            'sourcePort': [31337],
            'destination': ['10.0.0.1'],
            'destinationPort': [80],
            'startDateTime': ['6/14/2023 03:15'],
            'stopDateTime': ['6/14/2023 03:15']
        })

    # Streamlit app
    st.title("Network Traffic Prediction (RNN)")

    # Load the RNN model
    model_name = "rnn.h5"
    model = load_selected_model(model_name)

    if model is not None:
        st.write("RNN model loaded successfully")
        if st.button("Summary"):
            st.write("Model Summary:")
            stringlist = []
            model.summary(print_fn=lambda x: stringlist.append(x))
            short_model_summary = "\n".join(stringlist)
            st.text(short_model_summary)

        # Get user input
        appName = st.selectbox("App Name", ['Unknown_UDP', 'HTTPImageTransfer', 'DNS', 'HTTPWeb', 'SecureWeb',
            'SSH', 'POP', 'NetBIOS-IP', 'Unknown_TCP', 'WindowsFileSharing',
            'SMTP', 'NTP', 'FTP', 'WebMediaDocuments', 'MiscApplication',
            'ICMP', 'WebMediaAudio', 'PeerEnabler', 'IGMP', 'SSDP', 'IMAP',
            'WebFileTransfer', 'AOL-ICQ', 'Oracle', 'MSMQ', 'Authentication',
            'IRC', 'Filenet', 'Groove', 'Hotline', 'Real', 'Misc-DB',
            'Timbuktu', 'Google', 'OpenNap', 'Yahoo', 'Misc-Ports',
            'ManagementServices', 'Anet', 'XWindows', 'LDAP', 'Flowgen',
            'Squid', 'SNMP-Ports', 'MiscApp', 'NETBEUI', 'Misc-Mail-Port',
            'Tacacs', 'MDQS', 'SMS', 'Hosts2-Ns', 'TimeServer', 'MS-SQL',
            'BitTorrent', 'NortonAntiVirus', 'MSN', 'rexec',
            'Network-Config-Ports', 'MicrosoftMediaServer', 'StreamingAudio',
            'Citrix', 'IPSec', 'NNTPNews', 'Telnet', 'H.323', 'PostgreSQL',
            'rlogin', 'SSL-Shell', 'PCAnywhere', 'Webmin',
            'MSTerminalServices', 'dsp3270', 'Gnutella', 'Printer', 'Intellex',
            'Ingres', 'rsh', 'PPTP', 'SunRPC', 'RPC', 'RTSP', 'VNC', 'XFER',
            'POP-port', 'Common-P2P-Port', 'BGP', 'NFS', 'DNS-Port',
            'Web-Port', 'Common-Ports', 'GuptaSQLBase', 'OpenWindows',
            'Nessus', 'NortonGhost', 'Kazaa', 'WebMediaVideo', 'TFTP', 'SIP',
            'giop-ssl', 'MSN-Zone', 'SAP', 'iChat', 'SNA', 'IPX',
            'UpdateDaemon', 'MGCP', 'Blubster'])
        totalSourceBytes = st.number_input("Total Source Bytes", 0)
        totalDestinationBytes = st.number_input("Total Destination Bytes", 0)
        totalDestinationPackets = st.number_input("Total Destination Packets", 0)
        totalSourcePackets = st.number_input("Total Source Packets", 0)
        direction = st.selectbox("Direction", ['L2R', 'L2L', 'R2R', 'R2L'])
        sourceTCPFlagsDescription = st.text_input("Source TCP Flags Description", "NaN")
        destinationTCPFlagsDescription = st.text_input("Destination TCP Flags Description", "NaN")
        source = st.text_input("Source IP", "192.168.5.122")
        protocolName = st.selectbox("Protocol Name", ['udp_ip', 'tcp_ip', 'icmp_ip', 'ip', 'igmp', 'ipv6icmp'])
        sourcePort = st.number_input("Source Port", 0)  # Changed to start from 0
        destination = st.text_input("Destination IP", "224.0.0.25")
        destinationPort = st.number_input("Destination Port", 0)  # Changed to start from 0
        startDateTime = st.text_input("Start Date Time", "6/13/2010 23:57")
        stopDateTime = st.text_input("Stop Date Time", "6/14/2010 0:11")

       

        if st.button("Predict"):
            # Prepare the input data
            input_data = {
                "appName": appName,
                "totalSourceBytes": totalSourceBytes,
                "totalDestinationBytes": totalDestinationBytes,
                "totalDestinationPackets": totalDestinationPackets,
                "totalSourcePackets": totalSourcePackets,
                "direction": direction,
                "sourceTCPFlagsDescription": sourceTCPFlagsDescription,
                "destinationTCPFlagsDescription": destinationTCPFlagsDescription,
                "source": source,
                "protocolName": protocolName,
                "sourcePort": sourcePort,
                "destination": destination,
                "destinationPort": destinationPort,
                "startDateTime": startDateTime,
                "stopDateTime": stopDateTime
            }

            # Validate input
            is_valid, error_message = validate_input(input_data)
            
            if not is_valid:
                st.error(f"Invalid input: {error_message}")
            else:
                try:
                    data = pd.DataFrame([input_data])
                    st.write("Raw input data:")
                    st.write(data)
                    
                    preprocessed_data = preprocess_data(data)
                    st.write("Preprocessed data:")
                    st.write(preprocessed_data)
                    
                    st.write("Data shape:")
                    st.write(preprocessed_data.shape)
                    
                    st.write("Data types:")
                    st.write(preprocessed_data.dtypes)
                    
                   
                    st.write("Model input:")
                    st.write(preprocessed_data.values)
                    
                    # Make prediction using the preprocessed data
                    prediction, raw_prediction = predict_traffic(model, preprocessed_data)
                    
                    st.write(f"Raw prediction value: {raw_prediction:.4f}")
                    st.write(f"Prediction: {prediction}")

                    # Allow user to adjust threshold
                   
                    
                    
                    # Plot feature importance
                   

                except Exception as e:
                    
                    st.write("")
                  

        if st.button("Test with Known Attack Data"):
            attack_data = generate_attack_data()
            preprocessed_attack_data = preprocess_data(attack_data)
            prediction, raw_prediction = predict_traffic(model, preprocessed_attack_data)
            st.write(f"Known attack data prediction: {prediction}")
            st.write(f"Raw prediction value: {raw_prediction:.4f}")
