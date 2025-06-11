# Add these imports at the top of server.py
import asyncio
import websockets
import json
import os
import sys
import time
import threading
import subprocess
import signal
import psutil
from flask import Flask, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

# Modify the Flask app initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

# Add WebSocket client variables
websocket_client = None
websocket_task = None
websocket_connected = False

# Add process lock and process variables
process_lock = threading.Lock()
prediction_process = None
capture_process = None

# Add WebSocket client functions
async def connect_to_prediction_api():
    global websocket_client, websocket_connected

    try:
        # Connect to Prediction API WebSocket server
        websocket_client = await websockets.connect("ws://127.0.0.1:8765")
        websocket_connected = True
        print("Connected to Prediction API WebSocket")

        # Listen for messages from Prediction API
        async for message in websocket_client:
            try:
                data = json.loads(message)

                # Ignore "Start packet capture" messages - they're not for us
                if isinstance(data, dict) and data.get("message") == "Start packet capture":
                    print("Ignoring 'Start packet capture' message")
                    continue

                # Forward prediction results to frontend via SocketIO
                if websocket_connected:
                    # Filtering logic: ignore if both are BENIGN
                    ddos_pred = str(data.get("DDoS", {}).get("Prediction", "")).strip().upper()
                    ids_pred = str(data.get("IDS", {}).get("Prediction", "")).strip().upper()
                    if ddos_pred == "BENIGN" and ids_pred == "BENIGN":
                        continue  # Ignore, do not emit to frontend

                    socketio.emit('prediction_update', data)
                    print(f"Forwarded prediction to frontend: {data}")

            except json.JSONDecodeError:
                print("Failed to parse WebSocket message from Prediction API")
            except Exception as e:
                print(f"Error processing WebSocket message: {e}")

    except websockets.exceptions.ConnectionClosed:
        print("WebSocket connection to Prediction API closed")
        websocket_connected = False
    except Exception as e:
        print(f"WebSocket connection error: {e}")
        websocket_connected = False
    finally:
        websocket_client = None
        websocket_connected = False

def start_websocket_client():
    global websocket_task

    # Create new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        websocket_task = loop.create_task(connect_to_prediction_api())
        loop.run_until_complete(websocket_task)
    except Exception as e:
        print(f"WebSocket client error: {e}")
    finally:
        loop.close()

# Modify the start_prediction_api function
@app.route('/start-prediction-api', methods=['POST'])
def start_prediction_api():
    global prediction_process, websocket_task

    with process_lock:
        if prediction_process and prediction_process.poll() is None:
            return jsonify({"success": True, "message": "Prediction API already running"})

        try:
            # Start the Prediction API script
            prediction_process = subprocess.Popen(
                [sys.executable, "Prediction API.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # Wait for API to start
            time.sleep(3)

            if prediction_process.poll() is not None:
                stderr = prediction_process.stderr.read()
                return jsonify({"success": False, "error": f"Failed to start: {stderr}"})

            # Start WebSocket client in separate thread
            websocket_thread = threading.Thread(target=start_websocket_client)
            websocket_thread.daemon = True
            websocket_thread.start()

            # Wait a moment for WebSocket connection
            time.sleep(2)

            return jsonify({"success": True, "pid": prediction_process.pid, "websocket_connected": websocket_connected})

        except Exception as e:
            return jsonify({"success": False, "error": str(e)})

@app.route('/start-packet-capture', methods=['POST'])
def start_packet_capture():
    global capture_process

    with process_lock:
        if capture_process and capture_process.poll() is None:
            return jsonify({"success": True, "message": "Packet Capture already running"})

        try:
            # Start the Packet Capture API script
            capture_process = subprocess.Popen(
                [sys.executable, "Packet Capture API.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # Wait for API to start
            time.sleep(3)

            if capture_process.poll() is not None:
                stderr = capture_process.stderr.read()
                return jsonify({"success": False, "error": f"Failed to start: {stderr}"})

            return jsonify({"success": True, "pid": capture_process.pid})

        except Exception as e:
            return jsonify({"success": False, "error": str(e)})

# Modify the stop_services function
@app.route('/stop-services', methods=['POST'])
def stop_services():
    global prediction_process, capture_process, websocket_client, websocket_connected, websocket_task

    with process_lock:
        terminated = []

        # Close WebSocket connection first
        if websocket_client and websocket_connected:
            try:
                asyncio.create_task(websocket_client.close())
                websocket_connected = False
                terminated.append("WebSocket Connection")
                print("WebSocket connection closed")
            except Exception as e:
                print(f"Error closing WebSocket: {e}")

        # Stop packet capture process
        if capture_process and capture_process.poll() is None:
            try:
                kill_process_tree(capture_process.pid)
                terminated.append("Packet Capture")
            except Exception as e:
                print(f"Error stopping Packet Capture: {e}")

        # Stop prediction API process
        if prediction_process and prediction_process.poll() is None:
            try:
                kill_process_tree(prediction_process.pid)
                terminated.append("Prediction API")
            except Exception as e:
                print(f"Error stopping Prediction API: {e}")

        # Reset process variables
        prediction_process = None
        capture_process = None
        websocket_client = None
        websocket_connected = False

        return jsonify({
            "success": True,
            "terminated": terminated
        })

# Serve the frontend index.html at the root URL
@app.route('/')
def serve_index():
    return send_from_directory('Design', 'index.html')

# Optionally, serve other static files (like JS, CSS) from Design folder
@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('Design', filename)

# Add SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    print('Client connected to SocketIO')
    emit('status', {'connected': True})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected from SocketIO')

# Add health check endpoint
@app.route('/health-check', methods=['GET'])
def health_check():
    api_healthy = prediction_process and prediction_process.poll() is None
    capture_healthy = capture_process and capture_process.poll() is None

    return jsonify({
        "api_healthy": api_healthy,
        "capture_healthy": capture_healthy,
        "websocket_connected": websocket_connected
    })

def kill_port(port):
    """Kill all processes using the given port."""
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for conn in proc.connections(kind='inet'):
                if conn.laddr and conn.laddr.port == port:
                    print(f"Killing process {proc.pid} on port {port}")
                    proc.kill()
                    break
        except Exception:
            continue

def kill_process_tree(pid):
    """Kill a process and all its children."""
    try:
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            child.kill()
        parent.kill()
    except Exception as e:
        print(f"Error killing process tree for pid {pid}: {e}")

# Modify the main execution block
if __name__ == '__main__':
    def shutdown_handler(signum, frame):
        print("\nReceived shutdown signal. Cleaning up...")
        with process_lock:
            if websocket_client and websocket_connected:
                try:
                    asyncio.run(websocket_client.close())
                except Exception:
                    pass
            for process in [capture_process, prediction_process]:
                if process and process.poll() is None:
                    try:
                        kill_process_tree(process.pid)
                    except Exception:
                        pass
        # Kill servers on ports 8765 and 8000
        kill_port(8765)
        kill_port(8000)
        print("Cleanup complete. Exiting.")
        os._exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        # Ensure the frontend files exist in the Design folder
        if not os.path.exists(os.path.join('Design', 'index.html')):
            print("Creating frontend files in Design folder...")
            # ... existing code for creating templates ...

        # Use SocketIO instead of regular Flask
        socketio.run(app, host='127.0.0.1', port=8000,allow_unsafe_werkzeug=True)

    finally:
        # Clean up processes and WebSocket on server shutdown
        with process_lock:
            if websocket_client and websocket_connected:
                try:
                    asyncio.create_task(websocket_client.close())
                except:
                    pass

            for process in [capture_process, prediction_process]:
                if process and process.poll() is None:
                    try:
                        kill_process_tree(process.pid)
                    except:
                        pass
