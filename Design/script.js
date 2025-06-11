// Global variables
let predictionAPIProcess = null;
let packetCaptureProcess = null;
let webSocket = null;
let isRunning = false;
let reconnectAttempts = 0;
let maxReconnectAttempts = 5;
let reconnectInterval = null;
let socket = null;

// DOM Elements
const startBtn = document.getElementById('start-btn');
const stopBtn = document.getElementById('stop-btn');
const clearLogBtn = document.getElementById('clear-log-btn');
const apiStatus = document.getElementById('api-status');
const captureStatus = document.getElementById('capture-status');
const ddosStatus = document.getElementById('ddos-status');
const idsStatus = document.getElementById('ids-status');
const ddosTimestamp = document.getElementById('ddos-timestamp');
const idsTimestamp = document.getElementById('ids-timestamp');
const ddosAlert = document.getElementById('ddos-alert');
const idsAlert = document.getElementById('ids-alert');
const eventLog = document.getElementById('event-log');

// Event Listeners
document.addEventListener('DOMContentLoaded', initializeApp);
startBtn.addEventListener('click', startMonitoring);
stopBtn.addEventListener('click', stopMonitoring);
clearLogBtn.addEventListener('click', clearEventLog);

// Handle visibility change to pause/resume when tab is not active
document.addEventListener('visibilitychange', handleVisibilityChange);

// Handle online/offline status
window.addEventListener('online', handleOnlineStatus);
window.addEventListener('offline', handleOfflineStatus);

// Utility Functions
function updateStatus(element, isOnline, text) {
    const dot = element.querySelector('.status-dot');
    const statusText = element.querySelector('.status-text');

    if (isOnline) {
        dot.classList.remove('offline');
        dot.classList.add('online');
    } else {
        dot.classList.remove('online');
        dot.classList.add('offline');
    }

    statusText.textContent = text;

    // Add visual feedback
    element.style.transform = 'scale(1.02)';
    setTimeout(() => {
        element.style.transform = 'scale(1)';
    }, 200);
}

function addLogEntry(message, type = 'info') {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });

    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';

    const timeSpan = document.createElement('span');
    timeSpan.className = 'log-time';
    timeSpan.textContent = `[${timeStr}]`;

    const messageSpan = document.createElement('span');
    messageSpan.className = `log-message ${type}`;
    messageSpan.textContent = message;

    logEntry.appendChild(timeSpan);
    logEntry.appendChild(messageSpan);

    eventLog.appendChild(logEntry);

    // Auto scroll to bottom with smooth behavior
    eventLog.scrollTo({
        top: eventLog.scrollHeight,
        behavior: 'smooth'
    });

    // Limit log entries to prevent memory issues
    const logEntries = eventLog.children;
    if (logEntries.length > 100) {
        eventLog.removeChild(logEntries[0]);
    }

    // Show notification for critical events
    if (type === 'error' || type === 'warning') {
        showNotification(message, type);
    }
}

function clearEventLog() {
    eventLog.innerHTML = '';
    addLogEntry('Event log cleared', 'info');
}

function showNotification(message, type) {
    // Check if notifications are supported and permitted
    if ('Notification' in window && Notification.permission === 'granted') {
        const notification = new Notification('Network Security Monitor', {
            body: message,
            icon: '/favicon.ico',
            badge: '/favicon.ico',
            tag: 'security-alert'
        });

        // Auto close after 5 seconds
        setTimeout(() => {
            notification.close();
        }, 5000);
    }
}

function requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission().then(permission => {
            if (permission === 'granted') {
                addLogEntry('Notifications enabled', 'success');
            } else {
                addLogEntry('Notifications disabled', 'warning');
            }
        });
    }
}

function updateDetection(type, prediction) {
    const statusElement = type === 'DDoS' ? ddosStatus : idsStatus;
    const alertElement = type === 'DDoS' ? ddosAlert : idsAlert;
    const timestampElement = type === 'DDoS' ? ddosTimestamp : idsTimestamp;

    // Update timestamp with more detailed format
    const now = new Date();
    const timestamp = now.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
    timestampElement.textContent = `Last updated: ${timestamp}`;

    // Add visual feedback to the card
    const card = statusElement.closest('.card');
    card.style.transform = 'scale(1.02)';
    setTimeout(() => {
        card.style.transform = 'scale(1)';
    }, 300);

    // Update status and alert
    if (type === 'DDoS') {
        statusElement.textContent = prediction;

        if (prediction === 'Benign') {
            alertElement.textContent = '✅ No DDoS attack detected - Network traffic is normal';
            alertElement.className = 'alert-box normal';
        } else {
            alertElement.textContent = `🚨 DDoS attack detected: ${prediction}`;
            alertElement.className = 'alert-box danger';
            addLogEntry(`DDoS attack detected: ${prediction}`, 'error');
        }
    } else { // IDS
        statusElement.textContent = prediction;
        if (prediction === '0' || prediction === 0 || prediction === 'Normal') {
            alertElement.textContent = '✅ No intrusion detected - Network is secure';
            alertElement.className = 'alert-box normal';
        } else {
            alertElement.textContent = `⚠️ IDS attack detected: ${prediction}`;
            alertElement.className = 'alert-box danger';
            addLogEntry(`IDS attack detected: ${prediction}`, 'error');
        }
    }
}

function handleVisibilityChange() {
    if (document.hidden) {
        addLogEntry('Tab is not active - monitoring continues in background', 'info');
    } else {
        addLogEntry('Tab is now active', 'info');
    }
}

function handleOnlineStatus() {
    addLogEntry('Internet connection restored', 'success');
}

function handleOfflineStatus() {
    addLogEntry('Internet connection lost', 'warning');
}

function setLoadingState(isLoading, button) {
    if (isLoading) {
        button.disabled = true;
        const originalText = button.innerHTML;
        button.dataset.originalText = originalText;
        button.innerHTML = '<span class="btn-icon">⏳</span> Loading...';
    } else {
        button.disabled = false;
        if (button.dataset.originalText) {
            button.innerHTML = button.dataset.originalText;
            delete button.dataset.originalText;
        }
    }
}

// Enhanced API Functions with better error handling
async function startPredictionAPI() {
    try {
        addLogEntry('Initializing Prediction API...', 'info');

        // Use Python to run the Prediction API script
        const response = await fetch('/start-prediction-api', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                timestamp: Date.now()
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        if (data.success) {
            updateStatus(apiStatus, true, 'Prediction API: Online');
            addLogEntry('✅ Prediction API started successfully', 'success');
            return true;
        } else {
            throw new Error(data.error || 'Unknown error starting Prediction API');
        }
    } catch (error) {
        updateStatus(apiStatus, false, 'Prediction API: Failed');
        addLogEntry(`❌ Prediction API Error: ${error.message}`, 'error');
        return false;
    }
}

async function startPacketCapture() {
    try {
        addLogEntry('Initializing Packet Capture...', 'info');

        const response = await fetch('/start-packet-capture', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                timestamp: Date.now()
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        if (data.success) {
            updateStatus(captureStatus, true, 'Packet Capture: Online');
            addLogEntry('✅ Packet Capture started successfully', 'success');
            return true;
        } else {
            throw new Error(data.error || 'Unknown error starting Packet Capture');
        }
    } catch (error) {
        updateStatus(captureStatus, false, 'Packet Capture: Failed');
        addLogEntry(`❌ Packet Capture Error: ${error.message}`, 'error');
        return false;
    }
}

function connectSocketIO() {
    try {
        addLogEntry('🔌 Establishing SocketIO connection...', 'info');

        // Initialize SocketIO connection with limited reconnection attempts
        socket = io('http://localhost:8000', {
            reconnection: true,
            reconnectionAttempts: maxReconnectAttempts,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 30000,
            timeout: 2000
        });

        let serverUnreachableNotified = false;

        socket.on('connect', () => {
            addLogEntry('🔗 SocketIO connection established', 'success');
            reconnectAttempts = 0;
            serverUnreachableNotified = false;
            if (reconnectInterval) {
                clearInterval(reconnectInterval);
                reconnectInterval = null;
            }
        });

        socket.on('prediction_update', (data) => {
            try {
                if (data.error) {
                    addLogEntry(`Prediction Error: ${data.error}`, 'error');
                    return;
                }

                // Get predictions (case-insensitive)
                const ddosPred = data.DDoS && typeof data.DDoS.Prediction === 'string' ? data.DDoS.Prediction.trim().toUpperCase() : '';
                const idsPred = data.IDS && typeof data.IDS.Prediction === 'string' ? data.IDS.Prediction.trim().toUpperCase() : '';

                // Helper to reset a card
                function resetDetection(type) {
                    const statusElement = type === 'DDoS' ? ddosStatus : idsStatus;
                    const alertElement = type === 'DDoS' ? ddosAlert : idsAlert;
                    const timestampElement = type === 'DDoS' ? ddosTimestamp : idsTimestamp;
                    statusElement.textContent = 'No data';
                    timestampElement.textContent = '';
                    alertElement.textContent = '';
                    alertElement.className = 'alert-box';
                }

                // Logic for updating and resetting cards
                if (ddosPred !== 'BENIGN' && idsPred === 'BENIGN') {
                    updateDetection('DDoS', data.DDoS.Prediction);
                    addLogEntry(`DDoS Detection: ${data.DDoS.Prediction} (${data.DDoS.Probability}%)`, 'info');
                    resetDetection('IDS');
                } else if (ddosPred === 'BENIGN' && idsPred !== 'BENIGN') {
                    updateDetection('IDS', data.IDS.Prediction);
                    addLogEntry(`IDS Detection: ${data.IDS.Prediction} (${data.IDS.Probability}%)`, 'info');
                    resetDetection('DDoS');
                } else if (ddosPred !== 'BENIGN' && idsPred !== 'BENIGN') {
                    updateDetection('DDoS', data.DDoS.Prediction);
                    addLogEntry(`DDoS Detection: ${data.DDoS.Prediction} (${data.DDoS.Probability}%)`, 'info');
                    updateDetection('IDS', data.IDS.Prediction);
                    addLogEntry(`IDS Detection: ${data.IDS.Prediction} (${data.IDS.Probability}%)`, 'info');
                }

                // Log successful data reception if any card was updated
                if (ddosPred !== 'BENIGN' || idsPred !== 'BENIGN') {
                    addLogEntry('📊 Detection data received and processed', 'info');
                }

            } catch (error) {
                addLogEntry(`Failed to parse prediction data: ${error.message}`, 'error');
            }
        });

        socket.on('disconnect', (reason) => {
            addLogEntry(`🔌 SocketIO connection closed: ${reason}`, 'warning');
            updateStatus(apiStatus, false, 'Prediction API: Offline');
            updateStatus(captureStatus, false, 'Packet Capture: Offline');
            if (isRunning && reconnectAttempts < maxReconnectAttempts) {
                scheduleReconnect();
            } else if (isRunning && !serverUnreachableNotified) {
                addLogEntry('❌ Server unreachable. Stopping reconnection attempts.', 'error');
                showNotification('Server is offline. Please restart the server.', 'error');
                isRunning = false;
                startBtn.disabled = false;
                stopBtn.disabled = true;
                serverUnreachableNotified = true;
                showServerOfflineOverlay();
            }
        });

        socket.on('connect_error', (error) => {
            addLogEntry(`🔌 SocketIO connection error: ${error.message}`, 'error');
            updateStatus(apiStatus, false, 'Prediction API: Offline');
            updateStatus(captureStatus, false, 'Packet Capture: Offline');
            if (isRunning && reconnectAttempts < maxReconnectAttempts) {
                scheduleReconnect();
            } else if (isRunning && !serverUnreachableNotified) {
                addLogEntry('❌ Server unreachable. Stopping reconnection attempts.', 'error');
                showNotification('Server is offline. Please restart the server.', 'error');
                isRunning = false;
                startBtn.disabled = false;
                stopBtn.disabled = true;
                serverUnreachableNotified = true;
                showServerOfflineOverlay();
            }
        });

        socket.on('status', (data) => {
            addLogEntry('📡 Server status received', 'info');
        });

    } catch (error) {
        addLogEntry(`Failed to create SocketIO connection: ${error.message}`, 'error');
    }
}
function scheduleReconnect() {
    if (reconnectInterval) return; // Already scheduled

    reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000); // Exponential backoff, max 30s

    addLogEntry(`🔄 Attempting to reconnect SocketIO in ${delay/1000}s (attempt ${reconnectAttempts}/${maxReconnectAttempts})...`, 'warning');

    reconnectInterval = setTimeout(() => {
        reconnectInterval = null;
        if (isRunning) {
            connectSocketIO();
        }
    }, delay);
}


async function startMonitoring() {
    if (isRunning) return;

    try {
        setLoadingState(true, startBtn);
        addLogEntry('🚀 Starting monitoring system...', 'info');

        // Request notification permission
        requestNotificationPermission();

        // Start Prediction API first
        const apiStarted = await startPredictionAPI();
        if (!apiStarted) {
            addLogEntry('❌ Failed to start monitoring system - API initialization failed', 'error');
            return;
        }

        // Connect SocketIO for real-time updates
        await new Promise(resolve => setTimeout(resolve, 1000));
        connectSocketIO(); // Replace connectWebSocket() with this

        // Small delay to ensure connection is established
        addLogEntry('⏳ Waiting for connections to establish...', 'info');
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Start Packet Capture
        const captureStarted = await startPacketCapture();
        if (!captureStarted) {
            addLogEntry('⚠️ Packet capture failed, but API is running', 'warning');
        }

        // Update UI state
        startBtn.disabled = true;
        stopBtn.disabled = false;
        isRunning = true;

        addLogEntry('✅ Monitoring system is now active and ready', 'success');

        // Show success notification
        showNotification('Network monitoring started successfully', 'success');

    } catch (error) {
        addLogEntry(`❌ Failed to start monitoring: ${error.message}`, 'error');
        updateStatus(apiStatus, false, 'Prediction API: Failed');
        updateStatus(captureStatus, false, 'Packet Capture: Failed');
    } finally {
        setLoadingState(false, startBtn);
    }
}

async function stopMonitoring() {
    if (!isRunning) return;

    try {
        setLoadingState(true, stopBtn);
        addLogEntry('🛑 Stopping monitoring system...', 'info');

        // Clear reconnection attempts
        if (reconnectInterval) {
            clearInterval(reconnectInterval);
            reconnectInterval = null;
        }
        reconnectAttempts = 0;

        // Close SocketIO connection
        if (socket && socket.connected) {
            socket.disconnect();
            addLogEntry('🔌 SocketIO connection closed', 'info');
        }

        // Rest of the function remains the same...
        // Stop backend services
        const response = await fetch('/stop-services', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });

        if (!response.ok) {
            throw new Error(`Failed to stop services: HTTP ${response.status}`);
        }

        const data = await response.json();
        if (data.success) {
            addLogEntry('✅ Backend services stopped successfully', 'success');
        } else {
            addLogEntry(`⚠️ Warning: ${data.message || 'Some services may not have stopped cleanly'}`, 'warning');
        }

        // Update status indicators
        updateStatus(apiStatus, false, 'Prediction API: Offline');
        updateStatus(captureStatus, false, 'Packet Capture: Offline');

        // Reset detection displays
        ddosStatus.textContent = 'No data';
        idsStatus.textContent = 'No data';
        ddosTimestamp.textContent = '';
        idsTimestamp.textContent = '';
        ddosAlert.className = 'alert-box';
        idsAlert.className = 'alert-box';

        // Update UI state
        startBtn.disabled = false;
        stopBtn.disabled = true;
        isRunning = false;

        addLogEntry('✅ Monitoring system stopped successfully', 'success');

    } catch (error) {
        addLogEntry(`❌ Error stopping services: ${error.message}`, 'error');
    } finally {
        setLoadingState(false, stopBtn);
    }
}

// System Health Check
async function performHealthCheck() {
    if (!isRunning) return;

    try {
        const response = await fetch('/health-check', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });

        if (response.ok) {
            const data = await response.json();

            // Update status based on health check
            updateStatus(apiStatus, data.api_healthy,
                data.api_healthy ? 'Prediction API: Online' : 'Prediction API: Unhealthy');
            updateStatus(captureStatus, data.capture_healthy,
                data.capture_healthy ? 'Packet Capture: Online' : 'Packet Capture: Unhealthy');

            if (!data.api_healthy || !data.capture_healthy) {
                addLogEntry('⚠️ System health check detected issues', 'warning');
            }
        }
    } catch (error) {
        addLogEntry(`Health check failed: ${error.message}`, 'warning');
    }
}

// Initialize application
function initializeApp() {
    addLogEntry('🔧 System initialized and ready', 'info');
    addLogEntry('ℹ️ Click "Start Monitoring" to begin network security monitoring', 'info');

    // Check browser compatibility
    if (!window.WebSocket) {
        addLogEntry('❌ WebSocket not supported in this browser', 'error');
    }

    if (!window.fetch) {
        addLogEntry('❌ Fetch API not supported in this browser', 'error');
    }

    // Perform periodic health checks when running
    setInterval(() => {
        performHealthCheck();
    }, 30000); // Every 30 seconds

    // Show initial system status
    updateStatus(apiStatus, false, 'Prediction API: Offline');
    updateStatus(captureStatus, false, 'Packet Capture: Offline');
}

// Add overlay for server offline
function showServerOfflineOverlay() {
    if (document.getElementById('server-offline-overlay')) return;
    const overlay = document.createElement('div');
    overlay.id = 'server-offline-overlay';
    overlay.style.position = 'fixed';
    overlay.style.top = 0;
    overlay.style.left = 0;
    overlay.style.width = '100vw';
    overlay.style.height = '100vh';
    overlay.style.background = 'rgba(30,30,30,0.97)';
    overlay.style.zIndex = 9999;
    overlay.style.display = 'flex';
    overlay.style.flexDirection = 'column';
    overlay.style.justifyContent = 'center';
    overlay.style.alignItems = 'center';
    overlay.innerHTML = `
        <div style="color: #fff; font-size: 2rem; margin-bottom: 1.5rem; text-align: center;">
            🚫 Server is offline<br>Dashboard cannot function.<br><br>
            <span style='font-size:1.2rem;'>Please close this tab or restart the server.</span>
        </div>
        <button id="close-tab-btn" style="padding: 0.7em 2em; font-size: 1.2rem; background: #d32f2f; color: #fff; border: none; border-radius: 6px; cursor: pointer;">Close Tab</button>
    `;
    document.body.appendChild(overlay);
    document.getElementById('close-tab-btn').onclick = function() {
        window.close();
    };
}

// Enhanced cleanup on page unload
window.addEventListener('beforeunload', async (event) => {
    if (isRunning) {
        // Show confirmation dialog
        event.preventDefault();
        event.returnValue = 'Monitoring is active. Are you sure you want to leave?';

        // Attempt to stop services
        try {
            await fetch('/stop-services', {
                method: 'POST',
                keepalive: true // Ensure request completes even if page unloads
            });
        } catch (error) {
            console.error('Failed to stop services on page unload:', error);
        }
    }
});

// Handle window focus/blur for better resource management
window.addEventListener('focus', () => {
    if (isRunning) {
        addLogEntry('🔍 Window focused - resuming active monitoring', 'info');
    }
});

window.addEventListener('blur', () => {
    if (isRunning) {
        addLogEntry('💤 Window blurred - monitoring continues in background', 'info');
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', (event) => {
    // Ctrl+Shift+S to start monitoring
    if (event.ctrlKey && event.shiftKey && event.key === 'S') {
        event.preventDefault();
        if (!isRunning) {
            startMonitoring();
        }
    }

    // Ctrl+Shift+T to stop monitoring
    if (event.ctrlKey && event.shiftKey && event.key === 'T') {
        event.preventDefault();
        if (isRunning) {
            stopMonitoring();
        }
    }

    // Ctrl+Shift+C to clear log
    if (event.ctrlKey && event.shiftKey && event.key === 'C') {
        event.preventDefault();
        clearEventLog();
    }
});

// Export functions for debugging (only in development)
if (typeof window !== 'undefined' && window.location.hostname === 'localhost') {
    window.debugMonitor = {
        addLogEntry,
        updateDetection,
        performHealthCheck,
        isRunning: () => isRunning,
        getWebSocketState: () => webSocket ? webSocket.readyState : 'Not connected'
    };
}
