document.addEventListener("DOMContentLoaded", () => {
    // --- Application State ---
    let nodes = [];
    let links = [];
    let packetsLog = [];
    let alertCount = 0;
    
    // Limits
    const MAX_PACKETS_LOG = 100;
    
    // Filters
    let protocolFilter = "ALL";
    let severityFilter = "ALL";
    
    // Port distribution counters
    const portCounters = {
        80: 0,
        443: 0,
        22: 0,
        3389: 0
    };
    
    // --- UI Elements ---
    const totalMetricEl = document.getElementById("metric-total");
    const anomaliesMetricEl = document.getElementById("metric-anomalies");
    const threatScoreMetricEl = document.getElementById("metric-threat-score");
    const alertsContainer = document.getElementById("alerts-container");
    const alertCounterBadge = document.getElementById("alert-counter-badge");
    const packetStreamBody = document.getElementById("packet-stream-body");
    const connectionStatusEl = document.getElementById("connection-status");
    
    const protocolFilterEl = document.getElementById("protocol-filter");
    const severityFilterEl = document.getElementById("severity-filter");
    const resetZoomBtn = document.getElementById("reset-zoom-btn");
    const clearGraphBtn = document.getElementById("clear-graph-btn");
    
    // Tooltip
    const tooltip = d3.select("#tooltip");
    
    // --- Initialize D3.js Force Graph ---
    const canvas = document.getElementById("topology-canvas");
    const width = canvas.clientWidth || 700;
    const height = canvas.clientHeight || 450;
    
    const svg = d3.select("#topology-canvas")
        .append("svg")
        .attr("width", "100%")
        .attr("height", "100%")
        .attr("viewBox", `0 0 ${width} ${height}`)
        .attr("preserveAspectRatio", "xMidYMid meet");
        
    // Group container for zoom support
    const g = svg.append("g");
    
    // Setup Zoom
    const zoom = d3.zoom()
        .scaleExtent([0.2, 4])
        .on("zoom", (event) => {
            g.attr("transform", event.transform);
        });
        
    svg.call(zoom);
    
    // Remove loader once layout is established
    document.getElementById("graph-loader").style.opacity = 0;
    setTimeout(() => {
        document.getElementById("graph-loader").style.display = "none";
    }, 500);

    // Setup Force Simulation
    const simulation = d3.forceSimulation()
        .force("link", d3.forceLink().id(d => d.id).distance(120))
        .force("charge", d3.forceManyBody().strength(-150))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(25));
        
    // Render layers
    let linkGroup = g.append("g").attr("class", "links");
    let nodeGroup = g.append("g").attr("class", "nodes");
    
    // Dynamic updates
    function updateGraph() {
        // 1. Bind Links
        let linkSelection = linkGroup.selectAll("line")
            .data(links, d => d.id);
            
        linkSelection.exit().remove();
        
        let linkEnter = linkSelection.enter()
            .append("line")
            .attr("class", "link-line")
            .attr("stroke", d => {
                if (d.severity === "High") return "#ef4444";
                if (d.severity === "Medium") return "#f97316";
                if (d.severity === "Low") return "#eab308";
                return "#4b5563";
            })
            .attr("stroke-width", d => (d.severity === "High" || d.severity === "Medium") ? 2.5 : 1.5);
            
        linkSelection = linkEnter.merge(linkSelection);
        
        // 2. Bind Nodes
        let nodeSelection = nodeGroup.selectAll("g")
            .data(nodes, d => d.id);
            
        nodeSelection.exit().remove();
        
        let nodeEnter = nodeSelection.enter()
            .append("g")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended)
            );
            
        nodeEnter.append("circle")
            .attr("class", "node-circle")
            .attr("r", d => d.anomaly ? 12 : 9)
            .attr("fill", d => d.anomaly ? "#ef4444" : "#3b82f6")
            .attr("stroke", d => d.anomaly ? "rgba(239, 68, 68, 0.4)" : "rgba(59, 130, 246, 0.4)")
            .style("filter", d => d.anomaly ? "drop-shadow(0 0 10px #ef4444)" : "none");
            
        nodeEnter.append("text")
            .attr("class", "node-label")
            .attr("dx", 14)
            .attr("dy", ".35em")
            .text(d => d.label);
            
        nodeSelection = nodeEnter.merge(nodeSelection);
        
        // Setup tooltip hovers
        nodeSelection.on("mouseover", (event, d) => {
            tooltip.transition().duration(100).style("opacity", 1);
            tooltip.html(`
                <div class="tooltip-title"><i class="fa-solid fa-server"></i> IP Node Details</div>
                <div class="tooltip-row"><strong>IP Address:</strong> ${d.id}</div>
                <div class="tooltip-row"><strong>Threat Status:</strong> <span style="color: ${d.anomaly ? '#ef4444' : '#22c55e'}">${d.anomaly ? 'COMPROMISED / ANOMALOUS' : 'Clean'}</span></div>
                <div class="tooltip-row"><strong>Last Synced:</strong> ${new Date(d.last_active * 1000).toLocaleTimeString()}</div>
            `);
        })
        .on("mousemove", (event) => {
            tooltip
                .style("left", (event.pageX + 15) + "px")
                .style("top", (event.pageY - 20) + "px");
        })
        .on("mouseout", () => {
            tooltip.transition().duration(100).style("opacity", 0);
        });
        
        // Restart simulation
        simulation.nodes(nodes);
        simulation.force("link").links(links);
        simulation.alpha(0.3).restart();
        
        // Simulation Tick handler
        simulation.on("tick", () => {
            linkSelection
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
                
            nodeSelection
                .attr("transform", d => `translate(${d.x}, ${d.y})`);
        });
    }
    
    // Simulation Drag handlers
    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    
    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
    
    // Zoom control actions
    resetZoomBtn.addEventListener("click", () => {
        svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
    });
    
    clearGraphBtn.addEventListener("click", () => {
        nodes = [];
        links = [];
        updateGraph();
    });
    
    // --- Load historical database data ---
    async function loadHistory() {
        try {
            // Load Topology
            const topoRes = await fetch("/topology");
            if (topoRes.ok) {
                const topoData = await topoRes.json();
                nodes = topoData.nodes || [];
                links = topoData.edges || [];
                updateGraph();
            }
            
            // Load Alerts
            const alertsRes = await fetch("/alerts?limit=15");
            if (alertsRes.ok) {
                const alertsData = await alertsRes.json();
                if (alertsData && alertsData.length > 0) {
                    // Remove "no alerts" placeholder
                    const placeholder = alertsContainer.querySelector(".no-alerts-msg");
                    if (placeholder) placeholder.style.display = "none";
                    
                    alertsData.forEach(alert => prependAlertCard(alert));
                    alertCount = alertsData.length;
                    alertCounterBadge.textContent = `${alertCount} DETECTED`;
                }
            }
        } catch (e) {
            console.error("Failed loading baseline database data:", e);
        }
    }
    
    // --- WebSocket Stream ---
    let socket;
    
    function connectWebSocket() {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${window.location.host}/ws/packets`;
        
        socket = new WebSocket(wsUrl);
        
        socket.onopen = () => {
            console.log("WebSocket connection established");
            connectionStatusEl.className = "status-badge connected";
            connectionStatusEl.innerHTML = `<span class="pulse-dot"></span> Streaming Live`;
        };
        
        socket.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                if (message.type === "packet") {
                    handleLivePacket(message.data);
                } else if (message.type === "alert") {
                    handleLiveAlert(message.data);
                }
            } catch (e) {
                console.error("Error parsing WebSocket JSON payload:", e);
            }
        };
        
        socket.onerror = (error) => {
            console.error("WebSocket socket error:", error);
        };
        
        socket.onclose = () => {
            console.log("WebSocket connection closed. Retrying in 4 seconds...");
            connectionStatusEl.className = "status-badge disconnected";
            connectionStatusEl.innerHTML = `<span class="pulse-dot"></span> Sniffer Offline`;
            setTimeout(connectWebSocket, 4000);
        };
    }
    
    // --- Real-time updates handler ---
    
    function handleLivePacket(pkt) {
        // Prepend to packet log array
        packetsLog.unshift(pkt);
        if (packetsLog.length > MAX_PACKETS_LOG) {
            packetsLog.pop();
        }
        
        // Update ports count if port is relevant
        const dport = pkt.dport;
        if (dport in portCounters) {
            portCounters[dport] += 1;
            updatePortCharts();
        }
        
        // Increment metrics total
        const total = parseInt(totalMetricEl.textContent) + 1;
        totalMetricEl.textContent = total;
        
        // Average threat score update
        const avgThreat = (parseFloat(threatScoreMetricEl.textContent) * (total - 1) + pkt.threat_score) / total;
        threatScoreMetricEl.textContent = avgThreat.toFixed(2);
        
        // Update topology local state
        syncTopologyFromPacket(pkt);
        
        // Render packet table row
        renderPacketRow(pkt);
    }
    
    function handleLiveAlert(alert) {
        // Prepend to alert panel
        const placeholder = alertsContainer.querySelector(".no-alerts-msg");
        if (placeholder) placeholder.style.display = "none";
        
        prependAlertCard(alert);
        
        // Update metrics
        alertCount += 1;
        alertCounterBadge.textContent = `${alertCount} DETECTED`;
        anomaliesMetricEl.textContent = alertCount;
    }
    
    function syncTopologyFromPacket(pkt) {
        const srcIp = pkt.src_ip;
        const dstIp = pkt.dst_ip;
        const severity = pkt.threat_level;
        
        // Check source node
        let srcNode = nodes.find(n => n.id === srcIp);
        if (!srcNode) {
            srcNode = { id: srcIp, label: srcIp, last_active: pkt.timestamp, anomaly: (severity === "High") };
            nodes.push(srcNode);
        } else {
            srcNode.last_active = pkt.timestamp;
            if (severity === "High") srcNode.anomaly = true;
        }
        
        // Check destination node
        let dstNode = nodes.find(n => n.id === dstIp);
        if (!dstNode) {
            dstNode = { id: dstIp, label: dstIp, last_active: pkt.timestamp, anomaly: false };
            nodes.push(dstNode);
        } else {
            dstNode.last_active = pkt.timestamp;
        }
        
        // Check edge
        const edgeId = `${srcIp}->${dstIp}`;
        let edge = links.find(l => l.id === edgeId);
        if (!edge) {
            links.push({
                id: edgeId,
                source: srcIp,
                target: dstIp,
                last_active: pkt.timestamp,
                severity: severity
            });
        } else {
            edge.last_active = pkt.timestamp;
            edge.severity = severity;
        }
        
        // Apply updates to simulation Graph
        updateGraph();
    }
    
    // --- Render Logic helper functions ---
    
    function renderPacketRow(pkt) {
        // Filter checks
        const showProto = (protocolFilter === "ALL" || pkt.protocol === protocolFilter);
        const showSeverity = (severityFilter === "ALL" || pkt.threat_level === severityFilter);
        
        if (!showProto || !showSeverity) return;
        
        const row = document.createElement("tr");
        
        const timeStr = new Date(pkt.timestamp * 1000).toLocaleTimeString();
        const sportStr = pkt.sport ? pkt.sport : "-";
        const dportStr = pkt.dport ? pkt.dport : "-";
        
        row.innerHTML = `
            <td>${timeStr}</td>
            <td><span class="badge ${pkt.protocol === 'TCP' ? 'badge-normal' : 'badge-low'}">${pkt.protocol}</span></td>
            <td>${pkt.src_ip}</td>
            <td>${pkt.dst_ip}</td>
            <td>${sportStr} &rarr; ${dportStr}</td>
            <td>${pkt.size} B</td>
            <td>${pkt.entropy.toFixed(3)}</td>
            <td>${pkt.isolation_forest_score.toFixed(3)}</td>
            <td>${pkt.autoencoder_reconstruction_error.toFixed(4)}</td>
            <td style="font-weight: 700;">${pkt.threat_score}%</td>
            <td><span class="badge" style="background: ${pkt.severity_color}25; color: ${pkt.severity_color}; border: 1px solid ${pkt.severity_color}40">${pkt.threat_level}</span></td>
        `;
        
        // Prepend to body
        if (packetStreamBody.children.length === 0) {
            packetStreamBody.appendChild(row);
        } else {
            packetStreamBody.insertBefore(row, packetStreamBody.firstChild);
        }
        
        // Trim table
        if (packetStreamBody.children.length > MAX_PACKETS_LOG) {
            packetStreamBody.removeChild(packetStreamBody.lastChild);
        }
    }
    
    function prependAlertCard(alert) {
        const card = document.createElement("div");
        card.className = `alert-item level-${alert.threat_level.toLowerCase()}`;
        
        const timeStr = new Date(alert.timestamp * 1000).toLocaleTimeString();
        const icon = alert.threat_level === 'High' ? 'fa-triangle-exclamation' : 'fa-circle-exclamation';
        
        card.innerHTML = `
            <div class="alert-icon-wrapper">
                <i class="fa-solid ${icon}"></i>
            </div>
            <div class="alert-body">
                <div class="alert-title-row">
                    <span class="alert-title">${alert.threat_level.toUpperCase()} Threat Detected</span>
                    <span class="alert-time">${timeStr}</span>
                </div>
                <div class="alert-desc">
                    <strong>Source:</strong> ${alert.src_ip}:${alert.sport} &rarr; <strong>Dest:</strong> ${alert.dst_ip}:${alert.dport}
                    <br>
                    <strong>Reason:</strong> ${alert.anomaly_reason} (Score: ${alert.threat_score}%)
                </div>
            </div>
        `;
        
        if (alertsContainer.children.length === 0) {
            alertsContainer.appendChild(card);
        } else {
            alertsContainer.insertBefore(card, alertsContainer.firstChild);
        }
    }
    
    function updatePortCharts() {
        const maxVal = Math.max(...Object.values(portCounters), 1);
        
        for (const port in portCounters) {
            const count = portCounters[port];
            const pct = (count / maxVal) * 100;
            
            // Query progress element
            const labels = Array.from(document.querySelectorAll(".port-label"));
            const targetLabel = labels.find(el => el.textContent.includes(port));
            if (targetLabel) {
                const wrapper = targetLabel.parentElement;
                const progressFill = wrapper.querySelector(".port-progress-fill");
                const countText = wrapper.querySelector(".port-count");
                
                progressFill.style.width = `${pct}%`;
                countText.textContent = count;
            }
        }
    }
    
    // --- Filters Event Listeners ---
    
    protocolFilterEl.addEventListener("change", (e) => {
        protocolFilter = e.target.value;
        refreshIngestionTable();
    });
    
    severityFilterEl.addEventListener("change", (e) => {
        severityFilter = e.target.value;
        refreshIngestionTable();
    });
    
    function refreshIngestionTable() {
        // Clear current elements
        packetStreamBody.innerHTML = "";
        
        // Re-filter and render from memory packetsLog
        for (let i = packetsLog.length - 1; i >= 0; i--) {
            renderPacketRow(packetsLog[i]);
        }
    }
    
    // --- Load initial status ---
    loadHistory();
    connectWebSocket();
});
