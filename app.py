
import streamlit as st
import pandas as pd
import joblib

# Load trained model
model = joblib.load(
    "/content/drive/MyDrive/IDS_PROJECT/intrusion_detection_model.pkl"
)

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
    "Choose a CSV file",
    type=["csv"]
)

if uploaded_file is not None:

    data = pd.read_csv(uploaded_file)

    st.write("### Uploaded Data")
    st.dataframe(data.head())

    # Convert categorical values into numerical columns
    data_encoded = pd.get_dummies(data)

    # Match the columns used during model training
    data_encoded = data_encoded.reindex(
        columns=model.feature_names_in_,
        fill_value=0
    )

    # Predict
    predictions = model.predict(data_encoded)

    data["Prediction"] = [
        "Normal" if p == 0 else "Attack"
        for p in predictions
    ]

    normal_count = (predictions == 0).sum()
    attack_count = (predictions == 1).sum()

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Normal Traffic", normal_count)

    with col2:
        st.metric("Intrusions Detected", attack_count)

    st.subheader("Detection Results")
    st.dataframe(data)

    st.download_button(
        "Download Results",
        data.to_csv(index=False),
        "intrusion_detection_results.csv",
        "text/csv"
    )
