# Network Security Projects for Phising Data

An end-to-end machine learning project for detecting malicious network activity from network traffic data. The system processes network features, trains a classification model, and provides predictions through a Flask web application.

## Problem Statement

Network attacks can disrupt systems, expose sensitive information, and affect business operations. This project uses machine learning to analyze network traffic attributes and classify whether a connection is normal or potentially malicious.

## Key Highlights

- End-to-end machine learning pipeline
- Data ingestion from MongoDB
- Data validation using a defined schema
- Data transformation and feature preprocessing
- Model training and evaluation
- Prediction pipeline for new network data
- Flask-based web interface
- Logging and exception handling
- Modular project structure using OOP principles

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
