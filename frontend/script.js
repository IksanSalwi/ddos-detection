document.addEventListener('DOMContentLoaded', () => {
    // Initialize chart
    const ctx = document.getElementById('traffic-chart').getContext('2d');
    const trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array.from({length: 30}, (_, i) => i + 1),
            datasets: [{
                label: 'Requests per second',
                data: Array(30).fill(0),
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    // Update server status
    function updateServerStatus() {
        fetch('http://localhost:8080/')
            .then(response => {
                const serverId = response.headers.get('X-Backend-Server');
                if (serverId) {
                    document.querySelectorAll('.server').forEach(el => {
                        el.classList.remove('active');
                    });
                    
                    let serverNumber = '';
                    if (serverId.includes('backend1')) {
                        serverNumber = 'server1';
                    } else if (serverId.includes('backend2')) {
                        serverNumber = 'server2';
                    } else if (serverId.includes('backend3')) {
                        serverNumber = 'server3';
                    }

                    if(serverNumber) {
                        document.getElementById(serverNumber).classList.add('active');
                    }

                    const backendServerInfo = document.getElementById('backend-server-info');
                    backendServerInfo.innerHTML = `<p>Request served by: ${serverId}</p>`;
                }
            })
            .catch(error => console.error('Error fetching server status:', error));
    }

    // Update stats
    function updateStats() {
        fetch('http://localhost:8081/nginx-stats') // This would be a custom endpoint in real implementation
            .then(response => response.json())
            .then(data => {
                document.getElementById('request-count').textContent = data.requests;
                document.getElementById('ddos-blocks').textContent = data.ddosBlocks;
                document.getElementById('current-load').textContent = `${data.cpuLoad}%`;
                
                // Update chart
                trafficChart.data.datasets[0].data.shift();
                trafficChart.data.datasets[0].data.push(data.rps);
                trafficChart.update();
            });
    }

    // Test button
    document.getElementById('test-btn').addEventListener('click', () => {
        fetch('http://localhost:8080/')
            .then(response => {
                const serverId = response.headers.get('X-Backend-Server');
                const ddosScore = response.headers.get('X-DDoS-Score');
                const isMalicious = response.headers.get('X-Is-Malicious');
                
                const resultDiv = document.getElementById('test-result');
                resultDiv.innerHTML = `
                    <p>Server: ${serverId}</p>
                    <p>DDoS Score: ${ddosScore || 'N/A'}</p>
                    <p>Malicious: ${isMalicious || 'false'}</p>
                `;
            });
    });

    // Initial update
    updateServerStatus();
    updateStats();
    
    // Periodic updates
    setInterval(updateServerStatus, 5000);
    setInterval(updateStats, 2000);
});
