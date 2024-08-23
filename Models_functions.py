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
from tensorflow.keras.layers import GRU, LSTM
from tensorflow.keras.initializers import Orthogonal

def input_page():

    # Suppress TensorFlow warnings (optional)
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Suppresses INFO and WARNING messages

    # Set environment variable to disable oneDNN custom operations (optional)
    os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

    def load_selected_model(model_name):
        try:
            # Custom LSTM layer to handle the 'time_major' argument
            class CustomLSTM(LSTM):
                def _init_(self, *args, **kwargs):
                    kwargs.pop('time_major', None)  # Remove 'time_major' if present
                    kwargs.pop('implementation', None)  # Remove 'implementation' if present
                    super()._init_(*args, **kwargs)

            # Custom GRU layer to handle the 'time_major' and 'implementation' arguments
            class CustomGRU(GRU):
                def _init_(self, *args, **kwargs):
                    kwargs.pop('time_major', None)  # Remove 'time_major' if present
                    kwargs.pop('implementation', None)  # Remove 'implementation' if present
                    super()._init_(*args, **kwargs)

            # Custom objects dictionary
            custom_objects = {
                'KerasLayer': hub.KerasLayer,
                'Orthogonal': Orthogonal,
                'LSTM': CustomLSTM,
                'GRU': CustomGRU
            }

            # Load the model with custom objects
            model = load_model(model_name, custom_objects=custom_objects)
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
        data["source"] = data["source"].apply(
            lambda ip: struct.unpack("!I", socket.inet_aton(ip))[0]
        )
        data["destination"] = data["destination"].apply(
            lambda ip: struct.unpack("!I", socket.inet_aton(ip))[0]
        )
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

    # Streamlit app
    st.title("Network Traffic Prediction")

    # Dropdown menu to select the model
    model_name = st.selectbox("Select Model", ["rnn.h5", "lstm.h5", "gru.h5"])

    # Load the selected model
    model = load_selected_model(model_name)

    if model:
        st.write("Model loaded successfully")
        if st.button("Summary"):
            st.write("Model Summary:")
            stringlist = []
            model.summary(print_fn=lambda x: stringlist.append(x))
            short_model_summary = "\n".join(stringlist)
            st.text(short_model_summary)

    # Get user input
    appName = st.selectbox("App Name",['Unknown_UDP', 'HTTPImageTransfer', 'DNS', 'HTTPWeb', 'SecureWeb',
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
    totalSourceBytes = st.number_input("Total Source Bytes",0)
    totalDestinationBytes = st.number_input("Total Destination Bytes", 0)
    totalDestinationPackets = st.number_input("Total Destination Packets", 0)
    totalSourcePackets = st.number_input("Total Source Packets", 0)
    direction = st.selectbox("Direction", ['L2R', 'L2L', 'R2R', 'R2L'])
    sourceTCPFlagsDescription = st.text_input("Source TCP Flags Description", "NaN")
    destinationTCPFlagsDescription = st.text_input("Destination TCP Flags Description", "NaN")
    source = st.text_input("Source IP", "192.168.5.122")
    protocolName = st.selectbox("Protocol Name", ['udp_ip', 'tcp_ip', 'icmp_ip', 'ip', 'igmp', 'ipv6icmp'])
    sourcePort = st.number_input("Source Port", 5353)
    destination = st.text_input("Destination IP", "224.0.0.25")
    destinationPort = st.number_input("Destination Port", 53)
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
                data = preprocess_data(data)
                prediction = model.predict(data)

                if prediction[0][0] > 0.5:
                    st.write("Prediction: Attack")
                else:
                    st.write("Prediction: Normal")

                # Visualize the input features
            

            except Exception as e:
                st.error(f"An error occurred during prediction: {str(e)}")

    st.write("Note: This is a demo application. In a real-world scenario, ensure proper security measures are in place.")