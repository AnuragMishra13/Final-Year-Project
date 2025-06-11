from flask import Flask, request, jsonify
import joblib
import numpy as np
import json
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
try:
    from sklearn.exceptions import DataConversionWarning
    warnings.filterwarnings("ignore", category=DataConversionWarning)
except ImportError:
    pass
import asyncio
import websockets
import threading
import sys
import platform

app = Flask(__name__)

# Global flag to track model loading
models_loaded = False

# Load DDoS and IDS models
try:
    # DDoS Model joblib files
    ddos_model = joblib.load("./Models/DDoS/DDoS_catboost_model.joblib")
    ddos_scaler = joblib.load("./Models/DDoS/DDoS_scaler.joblib")
    ddos_encoder = joblib.load("./Models/DDoS/DDoS_label_encoder.joblib")

    # IDS Model joblib files
    ids_model = joblib.load("./Models/IDS/IDS_catboost_model.joblib")
    ids_scaler = joblib.load("./Models/IDS/IDS_scaler.joblib")
    ids_encoder = joblib.load("./Models/IDS/IDS_label_encoder.joblib")

    models_loaded = True
    print("All models loaded successfully")
except Exception as e:
    print(f"Error loading models: {e}")
    models_loaded = False

def process_prediction(data):
    try:
        # Initialize response dictionary
        result = {
            "Source_ip": data.get("Src_ip", "unknown"),
            "DDoS": None,
            "IDS": None
        }

        # Process DDoS features
        if "DDoS" in data and data["DDoS"]:
            try:
                features = np.array(data["DDoS"]).reshape(1, -1)
                scaled_features = ddos_scaler.transform(features)

                # Predict class and probabilities
                prediction = ddos_model.predict(scaled_features)[0]
                probabilities = ddos_model.predict_proba(scaled_features)[0]

                # Decode class name
                decoded_prediction = ddos_encoder.inverse_transform([prediction])[0]

                # Get probability of predicted class (convert to percentage)
                class_idx = ddos_model.classes_.tolist().index(prediction)
                probability = round(probabilities[class_idx] * 100, 2)

                result["DDoS"] = {
                    "Prediction": str(decoded_prediction),
                    "Probability": probability
                }

            except Exception as e:
                result["DDoS"] = {"error": f"DDoS prediction failed: {str(e)}"}

        # Process IDS features
        if "IDS" in data and data["IDS"]:
            try:
                features = np.array(data["IDS"]).reshape(1, -1)
                scaled_features = ids_scaler.transform(features)

                # Predict class and probabilities
                prediction = ids_model.predict(scaled_features)[0]
                probabilities = ids_model.predict_proba(scaled_features)[0]

                # Decode class name
                decoded_prediction = ids_encoder.inverse_transform([prediction])[0]

                # Get probability of predicted class (convert to percentage)
                class_idx = ids_model.classes_.tolist().index(prediction)
                probability = round(probabilities[class_idx] * 100, 2)

                result["IDS"] = {
                    "Prediction": str(decoded_prediction),
                    "Probability": probability
                }
            except Exception as e:
                result["IDS"] = {"error": f"IDS prediction failed: {str(e)}"}

        # Check if no valid predictions were made
        if result["DDoS"] is None and result["IDS"] is None:
            return {
                "Source_ip": data.get("Source_ip", "unknown"),
                "error": "No valid DDoS or IDS features provided"
            }

        return result

    except Exception as e:
        return {
            "Source_ip": data.get("Source_ip", "unknown"),
            "error": f"Prediction error: {str(e)}"
        }

# Flask HTTP endpoint for predictions (for testing)
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No input data provided"}), 400

        result = process_prediction(data)
        return jsonify(result), 200 if "error" not in result else 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# List to keep track of all connected WebSocket clients
connected_websockets = set()

# WebSocket handler
async def websocket_prediction(websocket, path=None):
    # Register client
    connected_websockets.add(websocket)
    try:
        # Send "Start packet capture" to this specific client (Packet Capture API)
        if models_loaded:
            await websocket.send(json.dumps({"message": "Start packet capture"}))
            print("Sent to client: Start packet capture")
        else:
            await websocket.send(json.dumps({"error": "Models not loaded"}))
            print("Error: Models not loaded")
            return

        async for message in websocket:  # Continuously listen for messages
            try:
                # Parse JSON data
                data_json = json.loads(message) if isinstance(message, str) else json.loads(message.decode('utf-8'))

                # Process the prediction and print
                result = process_prediction(data_json)
                print(f"Prediction Results: {json.dumps(result, indent=2)}")

                # Broadcast prediction result to all connected clients
                broadcast_message = json.dumps(result)
                websockets_to_remove = set()
                for ws in connected_websockets:
                    try:
                        await ws.send(broadcast_message)
                    except Exception as e:
                        print(f"Error sending to client: {e}")
                        websockets_to_remove.add(ws)
                # Remove any closed/broken websockets
                connected_websockets.difference_update(websockets_to_remove)

            except json.JSONDecodeError:
                print("WebSocket JSON Error: Invalid JSON format")
            except Exception as e:
                print(f"WebSocket Error processing message: {e}")

    except websockets.exceptions.ConnectionClosed:
        print("WebSocket Client disconnected")
    except Exception as e:
        print(f"WebSocket Error: {e}")
    finally:
        # Unregister client
        connected_websockets.discard(websocket)

# Run WebSocket server
async def start_websocket_server():
    # Use localhost for Windows compatibility
    server = await websockets.serve(websocket_prediction, "127.0.0.1", 8765)
    print("WebSocket server started at ws://127.0.0.1:8765")
    await server.wait_closed()

# Run Flask server function
def run_flask():
    # Use localhost for Windows compatibility and disable debug for threading
    app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False)

# Windows-specific event loop policy
def set_windows_event_loop_policy():
    if platform.system() == 'Windows':
        # Set the event loop policy to prevent issues on Windows
        if sys.version_info >= (3, 8):
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

if __name__ == "__main__":
    # Set Windows-specific event loop policy
    set_windows_event_loop_policy()

    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    print("Flask server starting on http://127.0.0.1:5001")
    print("WebSocket server starting on ws://127.0.0.1:8765")

    # Start WebSocket server in the main thread
    try:
        asyncio.run(start_websocket_server())
    except KeyboardInterrupt:
        print("\nShutting down Prediction API...")
    except Exception as e:
        print(f"Error in main: {e}")
        input("Press Enter to exit...")
