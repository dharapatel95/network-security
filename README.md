# Network Security Projects for Phising Data

An end-to-end machine learning project for detecting malicious network activity from network traffic data. The system processes network features, trains a classification model, and provides predictions through a Flask web application.

## Problem Statement

Network attacks can disrupt systems, expose sensitive information, and affect business operations. This project uses machine learning to analyze network traffic attributes and classify whether a connection is normal or potentially malicious.


## Architecture

```text
Network Data
     │
     ▼
MongoDB Data Ingestion
     │
     ▼
Data Validation
     │
     ▼
Data Transformation
     │
     ▼
Model Training & Evaluation
     │
     ▼
Saved Model Artifacts
     │
     ▼
Flask Prediction Application
```
## Installation
git clone https://github.com/dharapatel95/network-security.git
cd network-security
py -3.11 -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

## MongoDB Setup
Create a .env file and add:
MONGODB_URL_KEY=your_mongodb_connection_string

## Run Training Pipeline
python main.py

## Run Flask App
python app.py


