import streamlit as st
import pandas as pd
import joblib

# Load trained model
model = joblib.load("intrusion_detection_model.pkl")

st.set_page_config(
    page_title="Intrusion Detection System",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Intrusion Detection System")
st.write("Machine Learning Based Network Intrusion Detection")

st.divider()

st.subheader("Upload Network Traffic Data")

uploaded_file = st.file_uploader(
    "Upload NSL-KDD Test Data",
    type=["txt", "csv"]
)

columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count',
    'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

if uploaded_file is not None:

    if uploaded_file.name.endswith(".txt"):

        data = pd.read_csv(
            uploaded_file,
            names=columns + ["attack", "difficulty"]
        )

        prediction_data = data[columns].copy()

    else:

        data = pd.read_csv(uploaded_file)

        prediction_data = data.drop(
            columns=[
                "attack",
                "difficulty",
                "label",
                "Prediction"
            ],
            errors="ignore"
        )

    # Convert categorical data
    encoded_data = pd.get_dummies(prediction_data)

    # Match model training columns
    encoded_data = encoded_data.reindex(
        columns=model.feature_names_in_,
        fill_value=0
    )

    # Make predictions
    predictions = model.predict(encoded_data)

    data["Prediction"] = [
        "Normal" if p == 0 else "Attack"
        for p in predictions
    ]

    normal_count = (predictions == 0).sum()
    attack_count = (predictions == 1).sum()

    st.success("✅ Intrusion detection completed!")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Normal Traffic", normal_count)

    with col2:
        st.metric("Intrusions Detected", attack_count)

    st.divider()

    st.subheader("Detection Results")

    st.dataframe(data)

    st.download_button(
        "Download Results",
        data.to_csv(index=False),
        "intrusion_detection_results.csv",
        "text/csv"
    )

