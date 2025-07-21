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
        fetch('http://localhost:8080/detect')
            .then(response => {
                const serverId = response.headers.get('x-backend-server');
                if (serverId) {
                    document.querySelectorAll('.server').forEach(el => {
                        el.classList.remove('active');
                    });
                    document.getElementById(serverId).classList.add('active');
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
        fetch('http://localhost:8080/detect')
            .then(response => {
                const serverId = response.headers.get('x-backend-server');
                const ddosScore = response.headers.get('ddos-score');
                const isMalicious = response.headers.get('is-malicious');
                
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
