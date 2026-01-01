// Argus RMT - Web Dashboard Application
// Main JavaScript file

(function() {
    'use strict';

    // ==========================================================================
    // Configuration
    // ==========================================================================
    
    const Config = {
        API_URL: window.location.origin + '/api/v1',
        WS_URL: (window.location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + window.location.host + '/api/v1/ws',
        REFRESH_INTERVAL: 30000,  // 30 seconds
        HEARTBEAT_INTERVAL: 15000, // 15 seconds
        MAX_TERMINAL_LINES: 500,
        MAX_ACTIVITY_ITEMS: 50
    };

    // ==========================================================================
    // State Management
    // ==========================================================================
    
    const State = {
        token: localStorage.getItem('argus_token'),
        user: null,
        selectedAgentId: null,
        agents: [],
        stats: null,
        ws: null,
        wsReconnectAttempts: 0,
        maxWsReconnectAttempts: 5
    };

    // ==========================================================================
    // API Client
    // ==========================================================================
    
    const API = {
        async request(endpoint, options = {}) {
            const url = Config.API_URL + endpoint;
            const headers = {
                'Content-Type': 'application/json',
                ...options.headers
            };

            if (State.token) {
                headers['Authorization'] = 'Bearer ' + State.token;
            }

            try {
                const response = await fetch(url, {
                    ...options,
                    headers
                });

                if (response.status === 401) {
                    App.logout();
                    throw new Error('Session expired');
                }

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.message || 'Request failed');
                }

                if (response.status === 204) {
                    return null;
                }

                return response.json();
            } catch (error) {
                console.error('API Error:', error);
                throw error;
            }
        },

        get(endpoint) {
            return this.request(endpoint);
        },

        post(endpoint, data) {
            return this.request(endpoint, {
                method: 'POST',
                body: JSON.stringify(data)
            });
        },

        put(endpoint, data) {
            return this.request(endpoint, {
                method: 'PUT',
                body: JSON.stringify(data)
            });
        },

        delete(endpoint) {
            return this.request(endpoint, {
                method: 'DELETE'
            });
        }
    };

    // ==========================================================================
    // WebSocket Handler
    // ==========================================================================
    
    const WS = {
        connect() {
            if (State.ws && State.ws.readyState === WebSocket.OPEN) {
                return;
            }

            const url = Config.WS_URL + '?token=' + State.token;
            State.ws = new WebSocket(url);

            State.ws.onopen = () => {
                console.log('WebSocket connected');
                State.wsReconnectAttempts = 0;
                this.startHeartbeat();
            };

            State.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                } catch (error) {
                    console.error('WebSocket message error:', error);
                }
            };

            State.ws.onclose = () => {
                console.log('WebSocket closed');
                this.stopHeartbeat();
                this.reconnect();
            };

            State.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
        },

        disconnect() {
            if (State.ws) {
                State.ws.close();
                State.ws = null;
            }
            this.stopHeartbeat();
        },

        reconnect() {
            if (State.wsReconnectAttempts >= State.maxWsReconnectAttempts) {
                console.log('Max reconnect attempts reached');
                return;
            }

            State.wsReconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, State.wsReconnectAttempts), 30000);
            
            console.log(`Reconnecting in ${delay}ms (attempt ${State.wsReconnectAttempts})`);
            setTimeout(() => this.connect(), delay);
        },

        handleMessage(data) {
            switch (data.type) {
                case 'agents':
                    State.agents = data.data;
                    UI.renderAgentList();
                    break;
                case 'agent_status':
                    this.updateAgentStatus(data.data);
                    break;
                case 'command_result':
                    UI.addCommandResult(data.data);
                    break;
                case 'alert':
                    UI.showAlert(data.data);
                    break;
                case 'stats':
                    State.stats = data.data;
                    UI.renderStats();
                    break;
            }
        },

        updateAgentStatus(data) {
            const agent = State.agents.find(a => a.id === data.agent_id);
            if (agent) {
                agent.status = data.status;
                agent.last_seen = data.last_seen;
                UI.renderAgentList();
            }
        },

        send(type, data) {
            if (State.ws && State.ws.readyState === WebSocket.OPEN) {
                State.ws.send(JSON.stringify({ type, data }));
            }
        },

        heartbeatInterval: null,

        startHeartbeat() {
            this.heartbeatInterval = setInterval(() => {
                this.send('ping', {});
            }, Config.HEARTBEAT_INTERVAL);
        },

        stopHeartbeat() {
            if (this.heartbeatInterval) {
                clearInterval(this.heartbeatInterval);
                this.heartbeatInterval = null;
            }
        }
    };

    // ==========================================================================
    // UI Handler
    // ==========================================================================
    
    const UI = {
        elements: {},

        init() {
            this.elements = {
                loginContainer: document.getElementById('loginContainer'),
                dashboard: document.getElementById('dashboard'),
                loginForm: document.getElementById('loginForm'),
                currentUser: document.getElementById('currentUser'),
                totalAgents: document.getElementById('totalAgents'),
                onlineAgents: document.getElementById('onlineAgents'),
                offlineAgents: document.getElementById('offlineAgents'),
                pendingCommands: document.getElementById('pendingCommands'),
                agentList: document.getElementById('agentList'),
                agentSearch: document.getElementById('agentSearch'),
                terminal: document.getElementById('terminal'),
                commandInput: document.getElementById('commandInput'),
                selectedAgent: document.getElementById('selectedAgent'),
                activityList: document.getElementById('activityList')
            };

            this.bindEvents();
        },

        bindEvents() {
            // Login form
            if (this.elements.loginForm) {
                this.elements.loginForm.addEventListener('submit', (e) => {
                    e.preventDefault();
                    App.login();
                });
            }

            // Command input
            if (this.elements.commandInput) {
                this.elements.commandInput.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter' && State.selectedAgentId) {
                        const command = e.target.value.trim();
                        if (command) {
                            App.executeCommand(command);
                            e.target.value = '';
                        }
                    }
                });
            }

            // Agent search
            if (this.elements.agentSearch) {
                this.elements.agentSearch.addEventListener('input', (e) => {
                    this.filterAgents(e.target.value);
                });
            }

            // Keyboard shortcuts
            document.addEventListener('keydown', (e) => {
                // Ctrl+K to focus search
                if (e.ctrlKey && e.key === 'k') {
                    e.preventDefault();
                    this.elements.agentSearch?.focus();
                }
                // Escape to deselect agent
                if (e.key === 'Escape') {
                    App.deselectAgent();
                }
            });
        },

        showLogin() {
            if (this.elements.loginContainer) {
                this.elements.loginContainer.style.display = 'flex';
            }
            if (this.elements.dashboard) {
                this.elements.dashboard.style.display = 'none';
            }
        },

        showDashboard() {
            if (this.elements.loginContainer) {
                this.elements.loginContainer.style.display = 'none';
            }
            if (this.elements.dashboard) {
                this.elements.dashboard.style.display = 'block';
            }
        },

        renderStats() {
            if (State.stats) {
                this.setText('totalAgents', State.stats.total_agents);
                this.setText('onlineAgents', State.stats.online_agents);
                this.setText('offlineAgents', State.stats.offline_agents);
                this.setText('pendingCommands', State.stats.pending_commands);
            }
        },

        renderAgentList() {
            if (!this.elements.agentList) return;

            this.elements.agentList.innerHTML = State.agents.map(agent => `
                <div class="agent-item ${agent.id === State.selectedAgentId ? 'selected' : ''}"
                     onclick="App.selectAgent('${agent.id}', '${agent.hostname}')">
                    <div class="agent-info">
                        <div class="status-indicator ${agent.status} ${agent.status === 'online' ? 'pulse' : ''}"></div>
                        <div class="agent-details">
                            <h4>${this.escapeHtml(agent.hostname)}</h4>
                            <span>${agent.id.substring(0, 8)}...</span>
                        </div>
                    </div>
                    <div class="agent-meta">
                        <div class="os">${agent.os} ${agent.arch}</div>
                        <div class="ip">${agent.ip_address}</div>
                    </div>
                </div>
            `).join('');
        },

        filterAgents(search) {
            const items = this.elements.agentList?.querySelectorAll('.agent-item');
            if (!items) return;

            search = search.toLowerCase();
            items.forEach(item => {
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(search) ? 'flex' : 'none';
            });
        },

        addTerminalLine(text, type = 'output') {
            if (!this.elements.terminal) return;

            const line = document.createElement('div');
            line.className = `terminal-line ${type}`;
            line.textContent = text;
            this.elements.terminal.appendChild(line);

            // Limit lines
            while (this.elements.terminal.children.length > Config.MAX_TERMINAL_LINES) {
                this.elements.terminal.removeChild(this.elements.terminal.firstChild);
            }

            this.elements.terminal.scrollTop = this.elements.terminal.scrollHeight;
        },

        clearTerminal() {
            if (this.elements.terminal) {
                this.elements.terminal.innerHTML = '';
            }
        },

        addCommandResult(result) {
            if (result.agent_id !== State.selectedAgentId) return;

            if (result.success) {
                this.addTerminalLine(result.output, 'output');
            } else {
                this.addTerminalLine(result.error || 'Command failed', 'error');
            }
        },

        addActivityItem(item) {
            if (!this.elements.activityList) return;

            const iconClass = item.success ? 'success' : 'error';
            const icon = item.success ? '✓' : '✕';

            const html = `
                <div class="activity-item">
                    <div class="activity-icon ${iconClass}">${icon}</div>
                    <div class="activity-content">
                        <h4>${this.escapeHtml(item.message)}</h4>
                        <span>${item.agent_name || 'System'} • ${this.timeAgo(item.timestamp)}</span>
                    </div>
                </div>
            `;

            this.elements.activityList.insertAdjacentHTML('afterbegin', html);

            // Limit items
            while (this.elements.activityList.children.length > Config.MAX_ACTIVITY_ITEMS) {
                this.elements.activityList.removeChild(this.elements.activityList.lastChild);
            }
        },

        showAlert(alert) {
            // Simple notification
            const notification = document.createElement('div');
            notification.className = `notification notification-${alert.severity}`;
            notification.innerHTML = `
                <strong>${alert.title || 'Alert'}</strong>
                <p>${alert.message}</p>
            `;
            document.body.appendChild(notification);

            setTimeout(() => notification.remove(), 5000);
        },

        showError(message) {
            alert(message); // Simple implementation
        },

        // Utility methods
        setText(id, text) {
            const el = document.getElementById(id);
            if (el) el.textContent = text;
        },

        escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        timeAgo(timestamp) {
            const date = new Date(timestamp);
            const now = new Date();
            const seconds = Math.floor((now - date) / 1000);

            if (seconds < 60) return 'Just now';
            if (seconds < 3600) return Math.floor(seconds / 60) + ' min ago';
            if (seconds < 86400) return Math.floor(seconds / 3600) + ' hours ago';
            return Math.floor(seconds / 86400) + ' days ago';
        }
    };

    // ==========================================================================
    // Application
    // ==========================================================================
    
    const App = {
        async init() {
            UI.init();

            if (State.token) {
                try {
                    await this.loadUser();
                    UI.showDashboard();
                    WS.connect();
                    await this.refreshData();
                    this.startRefreshInterval();
                } catch (error) {
                    console.error('Init error:', error);
                    this.logout();
                }
            } else {
                UI.showLogin();
            }
        },

        async login() {
            const username = document.getElementById('username')?.value;
            const password = document.getElementById('password')?.value;

            if (!username || !password) {
                UI.showError('Please enter username and password');
                return;
            }

            try {
                const response = await API.post('/auth/login', { username, password });
                State.token = response.token;
                State.user = response.user;
                localStorage.setItem('argus_token', State.token);

                UI.showDashboard();
                UI.setText('currentUser', State.user.username);
                WS.connect();
                await this.refreshData();
                this.startRefreshInterval();
            } catch (error) {
                UI.showError(error.message || 'Login failed');
            }
        },

        logout() {
            State.token = null;
            State.user = null;
            State.selectedAgentId = null;
            localStorage.removeItem('argus_token');
            WS.disconnect();
            this.stopRefreshInterval();
            UI.showLogin();
        },

        async loadUser() {
            // Token validation happens on first API call
            const stats = await API.get('/dashboard/stats');
            State.stats = stats;
        },

        async refreshData() {
            try {
                const [agents, stats] = await Promise.all([
                    API.get('/agents'),
                    API.get('/dashboard/stats')
                ]);

                State.agents = agents.agents || agents;
                State.stats = stats;

                UI.renderAgentList();
                UI.renderStats();
            } catch (error) {
                console.error('Refresh error:', error);
            }
        },

        refreshInterval: null,

        startRefreshInterval() {
            this.refreshInterval = setInterval(() => {
                this.refreshData();
            }, Config.REFRESH_INTERVAL);
        },

        stopRefreshInterval() {
            if (this.refreshInterval) {
                clearInterval(this.refreshInterval);
                this.refreshInterval = null;
            }
        },

        selectAgent(id, hostname) {
            State.selectedAgentId = id;
            UI.renderAgentList();
            
            if (UI.elements.selectedAgent) {
                UI.elements.selectedAgent.textContent = hostname;
            }
            if (UI.elements.commandInput) {
                UI.elements.commandInput.disabled = false;
            }

            UI.clearTerminal();
            UI.addTerminalLine(`Connected to ${hostname}`, 'output');
        },

        deselectAgent() {
            State.selectedAgentId = null;
            UI.renderAgentList();
            
            if (UI.elements.selectedAgent) {
                UI.elements.selectedAgent.textContent = 'No agent selected';
            }
            if (UI.elements.commandInput) {
                UI.elements.commandInput.disabled = true;
            }
        },

        async executeCommand(command) {
            if (!State.selectedAgentId) {
                UI.showError('Please select an agent first');
                return;
            }

            UI.addTerminalLine(`$ ${command}`, 'command');

            try {
                const response = await API.post(`/agents/${State.selectedAgentId}/commands`, {
                    type: 'execute',
                    payload: { command },
                    timeout: 30
                });

                UI.addTerminalLine(`Command queued: ${response.command_id}`, 'output');
            } catch (error) {
                UI.addTerminalLine(`Error: ${error.message}`, 'error');
            }
        },

        async sendCommand(type) {
            if (!State.selectedAgentId) {
                UI.showError('Please select an agent first');
                return;
            }

            try {
                await API.post(`/agents/${State.selectedAgentId}/commands`, {
                    type: type,
                    payload: {},
                    timeout: 30
                });

                UI.addTerminalLine(`Sent ${type} command`, 'command');
            } catch (error) {
                UI.addTerminalLine(`Error: ${error.message}`, 'error');
            }
        },

        async refreshAgents() {
            await this.refreshData();
        }
    };

    // ==========================================================================
    // Initialize
    // ==========================================================================
    
    document.addEventListener('DOMContentLoaded', () => {
        App.init();
    });

    // Expose to global scope for inline event handlers
    window.App = App;
    window.logout = () => App.logout();
    window.refreshAgents = () => App.refreshAgents();
    window.sendCommand = (type) => App.sendCommand(type);

})();
