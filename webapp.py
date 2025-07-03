from flask import Flask, jsonify, render_template_string, request
import network as net

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Network Manager</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
            th { background-color: #f2f2f2; }
            input { width: 80px; padding: 5px; }
            button { padding: 5px 10px; background: #4CAF50; color: white; border: none; cursor: pointer; }
            button:hover { background: #45a049; }
            .chart-container { width: 90%; margin: 20px auto; }
            .refresh-btn { margin: 10px 0; }
            .status { color: #666; font-style: italic; }
        </style>
    </head>
    <body>
        <h1>Network Bandwidth Manager</h1>
        <p class="status">Interface: {{ interface }} | Plage IP: {{ ip_range }}</p>
        <button class="refresh-btn" onclick="refreshData()">Actualiser</button>
        <h2>Appareils connectés</h2>
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>MAC</th>
                    <th>Nom</th>
                    <th>Download (kbps)</th>
                    <th>Upload (kbps)</th>
                    <th>Limite DL</th>
                    <th>Limite UL</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="devicesTable"></tbody>
        </table>
        <div class="chart-container">
            <h2>Trafic réseau</h2>
            <canvas id="trafficChart"></canvas>
        </div>
        <script>
            let trafficChart;
            const interface = "{{ interface }}";
            const ipRange = "{{ ip_range }}";
            async function fetchData() {
                const res = await fetch('/data');
                return await res.json();
            }
            async function fetchDevices() {
                const res = await fetch('/devices');
                return await res.json();
            }
            async function setLimit(ip, limitType, value) {
                const numValue = value === '' ? null : parseFloat(value);
                await fetch('/set_limit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip: ip,
                        limit_type: limitType,
                        limit_value: numValue
                    })
                });
                refreshData();
            }
            function updateDevicesTable(devices) {
                const table = document.getElementById('devicesTable');
                table.innerHTML = '';
                devices.forEach(device => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${device.ip}</td>
                        <td>${device.mac}</td>
                        <td>${device.hostname}</td>
                        <td>${device.dl_rate.toFixed(2)}</td>
                        <td>${device.ul_rate.toFixed(2)}</td>
                        <td><input type="number" id="dl-${device.ip}" 
                               value="${device.dl_limit !== null ? device.dl_limit : ''}" 
                               placeholder="No limit"></td>
                        <td><input type="number" id="ul-${device.ip}" 
                               value="${device.ul_limit !== null ? device.ul_limit : ''}" 
                               placeholder="No limit"></td>
                        <td>
                            <button onclick="setLimit('${device.ip}', 'download', 
                                    document.getElementById('dl-${device.ip}').value)">
                                Set DL
                            </button>
                            <button onclick="setLimit('${device.ip}', 'upload', 
                                    document.getElementById('ul-${device.ip}').value)">
                                Set UL
                            </button>
                        </td>
                    `;
                    table.appendChild(row);
                });
            }
            function updateChart(data) {
                const ctx = document.getElementById('trafficChart').getContext('2d');
                if (!trafficChart) {
                    trafficChart = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: data.labels,
                            datasets: [
                                {
                                    label: 'Download (KB)',
                                    data: data.received,
                                    backgroundColor: 'rgba(54, 162, 235, 0.7)'
                                },
                                {
                                    label: 'Upload (KB)',
                                    data: data.sent,
                                    backgroundColor: 'rgba(255, 99, 132, 0.7)'
                                }
                            ]
                        },
                        options: {
                            responsive: true,
                            scales: {
                                y: { beginAtZero: true }
                            }
                        }
                    });
                } else {
                    trafficChart.data.labels = data.labels;
                    trafficChart.data.datasets[0].data = data.received;
                    trafficChart.data.datasets[1].data = data.sent;
                    trafficChart.update();
                }
            }
            async function refreshData() {
                try {
                    const [data, devices] = await Promise.all([fetchData(), fetchDevices()]);
                    updateDevicesTable(devices);
                    updateChart(data);
                } catch (error) {
                    console.error('Error:', error);
                }
            }
            refreshData();
            setInterval(refreshData, 5000);
        </script>
    </body>
    </html>
    """, interface=net.NETWORK_INTERFACE, ip_range=net.IP_RANGE)

@app.route("/data")
def get_data():
    return jsonify({
        "labels": list(net.stats.keys()),
        "sent": [round(v[0]/1024, 2) for v in net.stats.values()],
        "received": [round(v[1]/1024, 2) for v in net.stats.values()],
        "hostnames": [net.hostnames.get(ip, "inconnu") for ip in net.stats.keys()]
    })

@app.route("/devices")
def get_devices():
    result = []
    for device in net.devices:
        ip = device['ip']
        result.append({
            'ip': ip,
            'mac': device['mac'],
            'hostname': device['hostname'],
            'dl_rate': net.current_rates.get(ip, [0, 0])[0],
            'ul_rate': net.current_rates.get(ip, [0, 0])[1],
            'dl_limit': net.bandwidth_limits[ip][0],
            'ul_limit': net.bandwidth_limits[ip][1]
        })
    return jsonify(result)

@app.route("/set_limit", methods=["POST"])
def set_limit():
    data = request.json
    ip = data['ip']
    limit_type = data['limit_type']
    limit_value = data['limit_value']
    current_dl, current_ul = net.bandwidth_limits[ip]
    if limit_type == 'download':
        net.bandwidth_limits[ip] = (limit_value, current_ul)
    elif limit_type == 'upload':
        net.bandwidth_limits[ip] = (current_dl, limit_value)
    return jsonify({"status": "success"})