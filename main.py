
from flask import Flask, request, render_template, jsonify
from flask import redirect,url_for
import numpy as np
import pandas as pd
from keras.models import load_model
from flask_sqlalchemy import SQLAlchemy 

db = SQLAlchemy()
admin = Admin()
import tensorflow as tf
import pickle

app = Flask(__name__)

# Load the saved model and scalers

# model = load_model('Model5/ffnn.keras')
# scaler_X = pickle.load(open('Model5/scaler_X.pkl', 'rb'))
# scaler_y = pickle.load(open('Model5/scaler_y.pkl', 'rb'))

# model = load_model('Model6/Model_2_1.keras')
# scaler_X = pickle.load(open('Model6/scaler_X.pkl', 'rb'))
# scaler_y = pickle.load(open('Model6/scaler_y.pkl', 'rb'))

model = load_model('Model7/ffnn3.keras')
scaler_X = pickle.load(open('Model7/scaler_X.pkl', 'rb'))
scaler_y = pickle.load(open('Model7/scaler_y.pkl', 'rb'))


@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/home2', methods=['GET'])
def home2():
    return render_template('home2.html')

@app.route('/form', methods=['GET'])
def form():
    return render_template('form.html')



@app.route("/info", methods=['GET', 'POST'])
def info():
    return render_template('diseases.html')   

# @app.route('/predict', methods=['POST'])
# def predict():
#     frequency = float(request.form.get('frequency'))
#     amplitude = float(request.form.get('amplitude'))

#     try:
#         # Convert input to a DataFrame with column names
#         input_data = pd.DataFrame([[frequency, amplitude]], columns=['Frequency', 'Amplitude'])
#         input_data_scaled = scaler_X.transform(input_data)

#         # Make prediction and inverse transform the result
#         prediction_scaled = model.predict(input_data_scaled)
#         predictions = scaler_y.inverse_transform(prediction_scaled)

#         # Convert predictions to native Python types
#         predictions = predictions.astype(float)
#         predicted_mass = predictions[0, 0]
#         predicted_unbalance_force = predictions[0, 1]

#         # Define severity bins, labels, and map
#         bins = [0, 5, 10, 25, 40, 55, 65, np.inf]
#         labels = ['Negligible', 'Minor', 'Moderate', 'Significant', 'Serious', 'Severe', 'Critical']
#         severity_map = {'Negligible': 0, 'Minor': 1, 'Moderate': 2, 'Significant': 3, 'Serious': 4, 'Severe': 5, 'Critical': 6}

#         # Determine severity based on predicted mass
#         severity = pd.cut([predicted_mass],
#                           bins=bins,
#                           labels=labels,
#                           include_lowest=True).to_list()[0]  # Convert to list and get the first element
#         severity_numerical = severity_map[severity]

#         # Prepare data for rendering the template
#         result = {
#             'predicted_mass': predicted_mass,
#             'predicted_unbalance_force': predicted_unbalance_force,
#             'severity_name': severity,          # Name of severity (e.g., 'Moderate')
#             'severity_numerical': severity_numerical  # Numerical value of severity (e.g., 2)
#         }

#         print(result)

#         return render_template('result.html', **result)
    
#     except Exception as e:
#         return str(e)
    
    
    
    
    
    
# @app.route('/predict', methods=['POST'])
# def predict():
#     frequency = float(request.form.get('frequency'))
#     amplitude = float(request.form.get('amplitude'))
#     temperature = float(request.form.get('temperature'))
#     OperatingHours = float(request.form.get('OperatingHours'))
#     try:
#         # Convert input to a DataFrame with column names
#         input_data = pd.DataFrame([[frequency, amplitude,temperature,OperatingHours]], columns=['Frequency', 'Amplitude',"Temperature","OperatingHours"])
#         input_data_scaled = scaler_X.transform(input_data)

#         # Make prediction and inverse transform the result
#         prediction_scaled = model.predict(input_data_scaled)
#         predictions = scaler_y.inverse_transform(prediction_scaled)

#         # Convert predictions to native Python types
#         predictions = predictions.astype(float)
#         print(predictions)
#         predicted_mass = predictions[0, 0]
#         predicted_lifespan = predictions[0, 1]
#         predicted_unbalance_force = predictions[0, 2]

#         # Define severity bins, labels, and map
#         bins = [0, 5, 10, 25, 40, 55, 65, np.inf]
#         labels = ['Negligible', 'Minor', 'Moderate', 'Significant', 'Serious', 'Severe', 'Critical']
#         severity_map = {'Negligible': 0, 'Minor': 1, 'Moderate': 2, 'Significant': 3, 'Serious': 4, 'Severe': 5, 'Critical': 6}

#         # Determine severity based on predicted mass
#         severity = pd.cut([predicted_mass],
#                           bins=bins,
#                           labels=labels,
#                           include_lowest=True).to_list()[0]  # Convert to list and get the first element
#         severity_numerical = severity_map[severity]

#         # Prepare data for rendering the template
#         result = {
#             'predicted_mass': predicted_mass,
#             'predicted_unbalance_force': predicted_unbalance_force,
#             'severity_name': severity,          # Name of severity (e.g., 'Moderate')
#             'severity_numerical': severity_numerical,  # Numerical value of severity (e.g., 2)
#             "predicted_lifespan": predicted_lifespan
#         }

#         print(result)

#         return render_template('result.html', **result)
    
#     except Exception as e:
#         return str(e)
    
    
    
    
@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get input values from the form
        frequency = float(request.form.get('frequency'))
        amplitude = float(request.form.get('amplitude'))
        temperature = float(request.form.get('temperature'))
        operating_hours = float(request.form.get('OperatingHours'))
        print(frequency,amplitude,temperature,operating_hours)

        # Convert input to a DataFrame with column names
        input_data = pd.DataFrame([[amplitude, frequency, temperature, operating_hours]], 
                                  columns=['Amplitude', 'Frequency', 'Temperature', 'OperatingHours'])

        # Scale the input data using the loaded scaler
        input_data_scaled = scaler_X.transform(input_data)

        # Make prediction and inverse transform the result
        prediction_scaled = model.predict(input_data_scaled)
        predictions = scaler_y.inverse_transform(prediction_scaled)

        # Convert predictions to native Python types
        predicted_mass = float(predictions[0, 0])
        predicted_lifespan = float(predictions[0, 1])
        predicted_unbalance_force = float(predictions[0, 2])

        # Define severity bins, labels, and map
        bins = [0, 5, 10, 25, 40, 55, 65, np.inf]
        labels = ['Negligible', 'Minor', 'Moderate', 'Significant', 'Serious', 'Severe', 'Critical']
        severity_map = {'Negligible': 0, 'Minor': 1, 'Moderate': 2, 'Significant': 3, 'Serious': 4, 'Severe': 5, 'Critical': 6}

        # Determine severity based on predicted mass
        severity = pd.cut([predicted_mass], bins=bins, labels=labels, include_lowest=True).to_list()[0]
        severity_numerical = severity_map[severity]

        # Prepare data for rendering the template
        result = {
            'predicted_mass': predicted_mass,
            'predicted_unbalance_force': predicted_unbalance_force,
            'predicted_lifespan': predicted_lifespan,
            'severity_name': severity,
            'severity_numerical': severity_numerical
        }

        # Print the result for debugging purposes
        print(result)

        # Render the results in the result.html template
        return render_template('result.html', **result)

    except Exception as e:
        # Handle any exceptions that occur during processing
        return f"Error during prediction: {str(e)}"

if __name__ == '__main__':
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
    db.init_app(app)
    admin.init_app(app)
    app.run(debug=True,port=5000)