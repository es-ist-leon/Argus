/**
 * Argus Enterprise Remote Management - Web Dashboard
 * Main JavaScript Application
 */

(function() {
    'use strict';

    // =========================================================================
    // Configuration
    // =========================================================================

    const Config = {
        API_BASE: '/api/v1',
        WS_RECONNECT_DELAY: 5000,
        WS_MAX_RECONNECTS: 10,
        REFRESH_INTERVAL: 30000,
        TOAST_DURATION: 5000,
        MAX_TERMINAL_LINES: 1000
    };

    // =========================================================================
    // State Management
    // =========================================================================

    const State = {
        token: localStorage.getItem('argus_token'),
        user: JSON.parse(localStorage.getItem('argus_user') || 'null'),
        currentView: 'dashboard',
        agents: [],
        selectedAgent: null,
        stats: null,
        ws: null,
        wsReconnects: 0,
        commandHistory: [],
        commandHistoryIndex: -1
    };

    // =========================================================================
    // API Client
    // =========================================================================

    const API = {
        async request(method, endpoint, data = null) {
            const url = Config.API_BASE + endpoint;
            const options = {
                method,
                headers: {
                    'Content-Type': 'application/json'
                }
            };

            if (State.token) {
                options.headers['Authorization'] = 'Bearer ' + State.token;
            }

            if (data) {
                options.body = JSON.stringify(data);
            }

            try {
                const response = await fetch(url, options);

                if (response.status === 401) {
                    Argus.logout();
                    throw new Error('Session expired');
                }

                if (!response.ok) {
                    const error = await response.json().catch(() => ({}));
                    throw new Error(error.message || `HTTP ${response.status}`);
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

        get(endpoint) { return this.request('GET', endpoint); },
        post(endpoint, data) { return this.request('POST', endpoint, data); },
        put(endpoint, data) { return this.request('PUT', endpoint, data); },
        delete(endpoint) { return this.request('DELETE', endpoint); }
    };

    // =========================================================================
    // WebSocket Handler
    // =========================================================================

    const WS = {
        connect() {
            if (!State.token) return;

            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const url = `${protocol}//${window.location.host}${Config.API_BASE}/ws?token=${State.token}`;

            State.ws = new WebSocket(url);

            State.ws.onopen = () => {
                console.log('WebSocket connected');
                State.wsReconnects = 0;
                UI.toast('Connected to server', 'success');
            };

            State.ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    this.handleMessage(message);
                } catch (error) {
                    console.error('WebSocket message error:', error);
                }
            };

            State.ws.onclose = () => {
                console.log('WebSocket disconnected');
                this.reconnect();
            };

            State.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
        },

        reconnect() {
            if (State.wsReconnects >= Config.WS_MAX_RECONNECTS) {
                UI.toast('Connection lost. Please refresh the page.', 'error');
                return;
            }

            State.wsReconnects++;
            const delay = Config.WS_RECONNECT_DELAY * State.wsReconnects;
            console.log(`Reconnecting in ${delay}ms...`);
            setTimeout(() => this.connect(), delay);
        },

        disconnect() {
            if (State.ws) {
                State.ws.close();
                State.ws = null;
            }
        },

        handleMessage(message) {
            switch (message.type) {
                case 'agents':
                    State.agents = message.data || [];
                    UI.renderAgentLists();
                    Argus.refreshStats();
                    break;
                case 'agent_connected':
                    UI.addActivity('Agent connected', message.data.hostname, 'success');
                    break;
                case 'agent_disconnected':
                    UI.addActivity('Agent disconnected', message.data.hostname, 'warning');
                    break;
                case 'command_result':
                    if (message.data.agent_id === State.selectedAgent?.id) {
                        UI.addTerminalOutput(message.data);
                    }
                    break;
                case 'alert':
                    UI.toast(message.data.message, message.data.severity);
                    break;
            }
        },

        send(type, data) {
            if (State.ws && State.ws.readyState === WebSocket.OPEN) {
                State.ws.send(JSON.stringify({ type, data }));
            }
        }
    };

    // =========================================================================
    // UI Handler
    // =========================================================================

    const UI = {
        elements: {},

        init() {
            // Cache frequently used elements
            this.elements = {
                loginScreen: document.getElementById('loginScreen'),
                app: document.getElementById('app'),
                loginForm: document.getElementById('loginForm'),
                loginError: document.getElementById('loginError'),
                sidebar: document.getElementById('sidebar'),
                content: document.getElementById('content'),
                pageTitle: document.getElementById('pageTitle'),
                modalOverlay: document.getElementById('modalOverlay'),
                modalContainer: document.getElementById('modalContainer'),
                toastContainer: document.getElementById('toastContainer'),
                terminal: document.getElementById('terminal'),
                terminalInput: document.getElementById('terminalInput')
            };

            this.bindEvents();
        },

        bindEvents() {
            // Login form
            this.elements.loginForm?.addEventListener('submit', (e) => {
                e.preventDefault();
                Argus.login();
            });

            // Navigation
            document.querySelectorAll('[data-view]').forEach(link => {
                link.addEventListener('click', (e) => {
                    e.preventDefault();
                    const view = e.currentTarget.dataset.view;
                    Argus.navigateTo(view);
                });
            });

            // Settings navigation
            document.querySelectorAll('[data-settings]').forEach(link => {
                link.addEventListener('click', (e) => {
                    e.preventDefault();
                    const panel = e.currentTarget.dataset.settings;
                    this.showSettingsPanel(panel);
                });
            });

            // Mobile menu
            document.getElementById('mobileMenuBtn')?.addEventListener('click', () => {
                this.elements.sidebar?.classList.toggle('open');
            });

            // Terminal input
            this.elements.terminalInput?.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    Argus.executeCommand(e.target.value);
                    e.target.value = '';
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    this.navigateCommandHistory(-1);
                } else if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    this.navigateCommandHistory(1);
                }
            });

            // Terminal send button
            document.getElementById('terminalSendBtn')?.addEventListener('click', () => {
                const input = this.elements.terminalInput;
                if (input?.value) {
                    Argus.executeCommand(input.value);
                    input.value = '';
                }
            });

            // Global search
            document.getElementById('globalSearch')?.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    Argus.globalSearch(e.target.value);
                }
            });

            // Keyboard shortcuts
            document.addEventListener('keydown', (e) => {
                if (e.ctrlKey && e.key === 'k') {
                    e.preventDefault();
                    document.getElementById('globalSearch')?.focus();
                }
                if (e.key === 'Escape') {
                    this.closeModal();
                }
            });

            // Modal close on overlay click
            this.elements.modalOverlay?.addEventListener('click', (e) => {
                if (e.target === this.elements.modalOverlay) {
                    this.closeModal();
                }
            });

            // Dropdown handling
            document.addEventListener('click', (e) => {
                const dropdown = e.target.closest('.dropdown');
                document.querySelectorAll('.dropdown.open').forEach(d => {
                    if (d !== dropdown) d.classList.remove('open');
                });
                if (dropdown && e.target.closest('.dropdown-toggle')) {
                    dropdown.classList.toggle('open');
                }
            });

            // Agent filters
            ['agentSearch', 'agentStatusFilter', 'agentOsFilter'].forEach(id => {
                document.getElementById(id)?.addEventListener('input', () => {
                    this.filterAgents();
                });
            });
        },

        showLogin() {
            this.elements.loginScreen.style.display = 'flex';
            this.elements.app.style.display = 'none';
        },

        showApp() {
            this.elements.loginScreen.style.display = 'none';
            this.elements.app.style.display = 'flex';
        },

        navigateTo(view) {
            // Update navigation
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.toggle('active', item.dataset.view === view);
            });

            // Update views
            document.querySelectorAll('.view').forEach(v => {
                v.classList.toggle('active', v.id === `view-${view}`);
            });

            // Update title
            const titles = {
                dashboard: 'Dashboard',
                agents: 'Agents',
                terminal: 'Terminal',
                files: 'File Manager',
                tasks: 'Scheduled Tasks',
                groups: 'Agent Groups',
                audit: 'Audit Log',
                settings: 'Settings'
            };
            this.elements.pageTitle.textContent = titles[view] || view;

            State.currentView = view;

            // Close mobile menu
            this.elements.sidebar?.classList.remove('open');

            // Load view-specific data
            switch (view) {
                case 'agents':
                    Argus.refreshAgents();
                    break;
                case 'tasks':
                    Argus.loadTasks();
                    break;
                case 'groups':
                    Argus.loadGroups();
                    break;
                case 'audit':
                    Argus.loadAuditLog();
                    break;
                case 'settings':
                    Argus.loadSettings();
                    break;
            }
        },

        renderStats(stats) {
            document.getElementById('statTotalAgents').textContent = stats.total_agents || 0;
            document.getElementById('statOnlineAgents').textContent = stats.online_agents || 0;
            document.getElementById('statOfflineAgents').textContent = stats.offline_agents || 0;
            document.getElementById('statPendingCommands').textContent = stats.pending_commands || 0;
            document.getElementById('agentCount').textContent = stats.total_agents || 0;
        },

        renderAgentLists() {
            this.renderDashboardAgents();
            this.renderAgentsGrid();
            this.renderTerminalAgents();
            this.renderFilesAgents();
        },

        renderDashboardAgents() {
            const container = document.getElementById('dashboardAgentList');
            if (!container) return;

            if (State.agents.length === 0) {
                container.innerHTML = `
                    <div class="empty-state small">
                        <p>No agents connected</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = State.agents.slice(0, 10).map(agent => `
                <div class="agent-quick-item" onclick="Argus.selectAgent('${agent.id}')">
                    <span class="status-dot ${agent.status}"></span>
                    <span class="agent-name">${this.escape(agent.hostname)}</span>
                    <span class="agent-os">${agent.os}</span>
                </div>
            `).join('');
        },

        renderAgentsGrid() {
            const container = document.getElementById('agentsGrid');
            if (!container) return;

            if (State.agents.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                            <rect x="2" y="3" width="20" height="14" rx="2"/>
                            <line x1="8" y1="21" x2="16" y2="21"/>
                            <line x1="12" y1="17" x2="12" y2="21"/>
                        </svg>
                        <p>No agents found</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = State.agents.map(agent => `
                <div class="agent-card" onclick="Argus.selectAgent('${agent.id}')">
                    <div class="agent-card-header">
                        <span class="status-indicator ${agent.status}"></span>
                        <h4>${this.escape(agent.hostname)}</h4>
                        <span class="badge badge-${agent.status === 'online' ? 'success' : 'danger'}">${agent.status}</span>
                    </div>
                    <div class="agent-card-body">
                        <div class="agent-info-item">
                            <label>ID</label>
                            <span>${agent.id.substring(0, 8)}...</span>
                        </div>
                        <div class="agent-info-item">
                            <label>OS</label>
                            <span>${agent.os} ${agent.arch}</span>
                        </div>
                        <div class="agent-info-item">
                            <label>IP Address</label>
                            <span>${agent.ip_address}</span>
                        </div>
                        <div class="agent-info-item">
                            <label>Version</label>
                            <span>${agent.version || 'N/A'}</span>
                        </div>
                    </div>
                    <div class="agent-card-actions">
                        <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); Argus.openTerminalFor('${agent.id}')">
                            Terminal
                        </button>
                        <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); Argus.openFilesFor('${agent.id}')">
                            Files
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); Argus.disconnectAgent('${agent.id}')">
                            Disconnect
                        </button>
                    </div>
                </div>
            `).join('');
        },

        renderTerminalAgents() {
            const container = document.getElementById('terminalAgentList');
            if (!container) return;

            container.innerHTML = State.agents.filter(a => a.status === 'online').map(agent => `
                <div class="terminal-agent-item ${State.selectedAgent?.id === agent.id ? 'active' : ''}" 
                     onclick="Argus.selectAgentForTerminal('${agent.id}')">
                    <span class="status-dot ${agent.status}"></span>
                    <span>${this.escape(agent.hostname)}</span>
                </div>
            `).join('') || '<div class="empty-state small"><p>No online agents</p></div>';
        },

        renderFilesAgents() {
            const container = document.getElementById('filesAgentList');
            if (!container) return;

            container.innerHTML = State.agents.filter(a => a.status === 'online').map(agent => `
                <div class="terminal-agent-item ${State.selectedAgent?.id === agent.id ? 'active' : ''}"
                     onclick="Argus.selectAgentForFiles('${agent.id}')">
                    <span class="status-dot ${agent.status}"></span>
                    <span>${this.escape(agent.hostname)}</span>
                </div>
            `).join('') || '<div class="empty-state small"><p>No online agents</p></div>';
        },

        filterAgents() {
            const search = document.getElementById('agentSearch')?.value.toLowerCase() || '';
            const status = document.getElementById('agentStatusFilter')?.value || '';
            const os = document.getElementById('agentOsFilter')?.value.toLowerCase() || '';

            document.querySelectorAll('#agentsGrid .agent-card').forEach(card => {
                const text = card.textContent.toLowerCase();
                const cardStatus = card.querySelector('.badge')?.textContent.toLowerCase() || '';
                const cardOs = card.querySelector('.agent-info-item:nth-child(2) span')?.textContent.toLowerCase() || '';

                const matchSearch = !search || text.includes(search);
                const matchStatus = !status || cardStatus === status;
                const matchOs = !os || cardOs.includes(os);

                card.style.display = matchSearch && matchStatus && matchOs ? '' : 'none';
            });
        },

        clearTerminal() {
            if (this.elements.terminal) {
                this.elements.terminal.innerHTML = `
                    <div class="terminal-welcome">
                        <pre>
    _                           
   / \\   _ __ __ _ _   _ ___ 
  / _ \\ | '__/ _\` | | | / __|
 / ___ \\| | | (_| | |_| \\__ \\
/_/   \\_\\_|  \\__, |\\__,_|___/
             |___/           
                        </pre>
                        <p>Enterprise Remote Management Terminal</p>
                        <p class="text-muted">Ready for commands</p>
                    </div>
                `;
            }
        },

        addTerminalLine(text, type = 'output') {
            const terminal = this.elements.terminal;
            if (!terminal) return;

            // Remove welcome message if present
            const welcome = terminal.querySelector('.terminal-welcome');
            if (welcome) welcome.remove();

            const line = document.createElement('div');
            line.className = `terminal-line ${type}`;
            line.textContent = text;
            terminal.appendChild(line);

            // Limit lines
            while (terminal.children.length > Config.MAX_TERMINAL_LINES) {
                terminal.removeChild(terminal.firstChild);
            }

            terminal.scrollTop = terminal.scrollHeight;
        },

        addTerminalOutput(result) {
            if (result.success) {
                this.addTerminalLine(result.output || 'Command completed', 'output');
            } else {
                this.addTerminalLine(result.error || 'Command failed', 'error');
            }
        },

        navigateCommandHistory(direction) {
            if (State.commandHistory.length === 0) return;

            State.commandHistoryIndex += direction;
            State.commandHistoryIndex = Math.max(-1, Math.min(State.commandHistory.length - 1, State.commandHistoryIndex));

            if (State.commandHistoryIndex === -1) {
                this.elements.terminalInput.value = '';
            } else {
                this.elements.terminalInput.value = State.commandHistory[State.commandHistoryIndex];
            }
        },

        addActivity(message, source, type = 'info') {
            const container = document.getElementById('dashboardActivityList');
            if (!container) return;

            const emptyState = container.querySelector('.empty-state');
            if (emptyState) emptyState.remove();

            const icons = {
                success: '✓',
                warning: '!',
                error: '✕',
                info: 'i'
            };

            const item = document.createElement('div');
            item.className = 'activity-item';
            item.innerHTML = `
                <div class="activity-icon ${type}">${icons[type]}</div>
                <div class="activity-content">
                    <h4>${this.escape(message)}</h4>
                    <span>${this.escape(source)} • Just now</span>
                </div>
            `;

            container.insertBefore(item, container.firstChild);

            // Limit items
            while (container.children.length > 20) {
                container.removeChild(container.lastChild);
            }
        },

        showSettingsPanel(panel) {
            document.querySelectorAll('.settings-nav-item').forEach(item => {
                item.classList.toggle('active', item.dataset.settings === panel);
            });
            document.querySelectorAll('.settings-panel').forEach(p => {
                p.classList.toggle('active', p.id === `settings-${panel}`);
            });
        },

        showModal(type, data = {}) {
            const templates = {
                newTask: this.getNewTaskModal(),
                newGroup: this.getNewGroupModal(),
                newUser: this.getNewUserModal(),
                uploadFile: this.getUploadFileModal(),
                newApiKey: this.getNewApiKeyModal(),
                confirmDelete: this.getConfirmDeleteModal(data)
            };

            this.elements.modalContainer.innerHTML = templates[type] || '';
            this.elements.modalOverlay.classList.add('active');

            // Focus first input
            setTimeout(() => {
                this.elements.modalContainer.querySelector('input')?.focus();
            }, 100);
        },

        closeModal() {
            this.elements.modalOverlay.classList.remove('active');
        },

        getNewTaskModal() {
            return `
                <div class="modal-header">
                    <h3>New Scheduled Task</h3>
                    <button class="btn-icon" onclick="UI.closeModal()">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18"/>
                            <line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                </div>
                <div class="modal-body">
                    <form id="newTaskForm">
                        <div class="form-group">
                            <label>Task Name</label>
                            <input type="text" class="form-input" name="name" required>
                        </div>
                        <div class="form-group">
                            <label>Target Agent</label>
                            <select class="form-select" name="agent_id" required>
                                <option value="">Select agent...</option>
                                ${State.agents.map(a => `<option value="${a.id}">${a.hostname}</option>`).join('')}
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Command</label>
                            <textarea class="form-textarea" name="command" required placeholder="Enter command..."></textarea>
                        </div>
                        <div class="form-group">
                            <label>Schedule (Cron)</label>
                            <input type="text" class="form-input" name="schedule" placeholder="*/5 * * * *">
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="UI.closeModal()">Cancel</button>
                    <button class="btn btn-primary" onclick="Argus.createTask()">Create Task</button>
                </div>
            `;
        },

        getNewGroupModal() {
            return `
                <div class="modal-header">
                    <h3>New Agent Group</h3>
                    <button class="btn-icon" onclick="UI.closeModal()">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18"/>
                            <line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                </div>
                <div class="modal-body">
                    <form id="newGroupForm">
                        <div class="form-group">
                            <label>Group Name</label>
                            <input type="text" class="form-input" name="name" required>
                        </div>
                        <div class="form-group">
                            <label>Description</label>
                            <textarea class="form-textarea" name="description"></textarea>
                        </div>
                        <div class="form-group">
                            <label>Agents</label>
                            <div class="checkbox-group">
                                ${State.agents.map(a => `
                                    <label class="form-checkbox">
                                        <input type="checkbox" name="agents" value="${a.id}">
                                        <span>${a.hostname}</span>
                                    </label>
                                `).join('')}
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="UI.closeModal()">Cancel</button>
                    <button class="btn btn-primary" onclick="Argus.createGroup()">Create Group</button>
                </div>
            `;
        },

        getNewUserModal() {
            return `
                <div class="modal-header">
                    <h3>Add User</h3>
                    <button class="btn-icon" onclick="UI.closeModal()">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18"/>
                            <line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                </div>
                <div class="modal-body">
                    <form id="newUserForm">
                        <div class="form-group">
                            <label>Username</label>
                            <input type="text" class="form-input" name="username" required>
                        </div>
                        <div class="form-group">
                            <label>Email</label>
                            <input type="email" class="form-input" name="email" required>
                        </div>
                        <div class="form-group">
                            <label>Password</label>
                            <input type="password" class="form-input" name="password" required>
                        </div>
                        <div class="form-group">
                            <label>Role</label>
                            <select class="form-select" name="role" required>
                                <option value="viewer">Viewer</option>
                                <option value="operator">Operator</option>
                                <option value="admin">Administrator</option>
                            </select>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="UI.closeModal()">Cancel</button>
                    <button class="btn btn-primary" onclick="Argus.createUser()">Add User</button>
                </div>
            `;
        },

        getUploadFileModal() {
            return `
                <div class="modal-header">
                    <h3>Upload File</h3>
                    <button class="btn-icon" onclick="UI.closeModal()">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18"/>
                            <line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                </div>
                <div class="modal-body">
                    <form id="uploadFileForm">
                        <div class="form-group">
                            <label>Target Agent</label>
                            <select class="form-select" name="agent_id" required>
                                <option value="">Select agent...</option>
                                ${State.agents.filter(a => a.status === 'online').map(a => 
                                    `<option value="${a.id}">${a.hostname}</option>`
                                ).join('')}
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Destination Path</label>
                            <input type="text" class="form-input" name="path" placeholder="/path/to/destination">
                        </div>
                        <div class="form-group">
                            <label>File</label>
                            <input type="file" class="form-input" name="file" required>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="UI.closeModal()">Cancel</button>
                    <button class="btn btn-primary" onclick="Argus.uploadFile()">Upload</button>
                </div>
            `;
        },

        getNewApiKeyModal() {
            return `
                <div class="modal-header">
                    <h3>Generate API Key</h3>
                    <button class="btn-icon" onclick="UI.closeModal()">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18"/>
                            <line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                </div>
                <div class="modal-body">
                    <form id="newApiKeyForm">
                        <div class="form-group">
                            <label>Key Name</label>
                            <input type="text" class="form-input" name="name" required placeholder="e.g., CI/CD Integration">
                        </div>
                        <div class="form-group">
                            <label>Expiration</label>
                            <select class="form-select" name="expiration">
                                <option value="30">30 days</option>
                                <option value="90">90 days</option>
                                <option value="365">1 year</option>
                                <option value="0">Never</option>
                            </select>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="UI.closeModal()">Cancel</button>
                    <button class="btn btn-primary" onclick="Argus.generateApiKey()">Generate</button>
                </div>
            `;
        },

        getConfirmDeleteModal(data) {
            return `
                <div class="modal-header">
                    <h3>Confirm Delete</h3>
                    <button class="btn-icon" onclick="UI.closeModal()">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18"/>
                            <line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete <strong>${data.name || 'this item'}</strong>?</p>
                    <p class="text-muted">This action cannot be undone.</p>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="UI.closeModal()">Cancel</button>
                    <button class="btn btn-danger" onclick="Argus.confirmDelete('${data.type}', '${data.id}')">Delete</button>
                </div>
            `;
        },

        toast(message, type = 'info', duration = Config.TOAST_DURATION) {
            const container = this.elements.toastContainer;
            if (!container) return;

            const icons = {
                success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
                error: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
                warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
                info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
            };

            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.innerHTML = `
                <div class="toast-icon">${icons[type]}</div>
                <div class="toast-content">
                    <p>${this.escape(message)}</p>
                </div>
                <button class="toast-close" onclick="this.parentElement.remove()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                </button>
            `;

            container.appendChild(toast);

            setTimeout(() => {
                toast.style.animation = 'slideIn 0.3s ease reverse';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        },

        escape(text) {
            const div = document.createElement('div');
            div.textContent = text || '';
            return div.innerHTML;
        },

        formatDate(date) {
            return new Date(date).toLocaleString();
        },

        timeAgo(date) {
            const seconds = Math.floor((new Date() - new Date(date)) / 1000);
            if (seconds < 60) return 'Just now';
            if (seconds < 3600) return Math.floor(seconds / 60) + ' min ago';
            if (seconds < 86400) return Math.floor(seconds / 3600) + ' hours ago';
            return Math.floor(seconds / 86400) + ' days ago';
        }
    };

    // =========================================================================
    // Main Application
    // =========================================================================

    const Argus = {
        async init() {
            UI.init();

            if (State.token) {
                try {
                    await this.loadInitialData();
                    UI.showApp();
                    WS.connect();
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
            const errorEl = document.getElementById('loginError');

            if (!username || !password) {
                if (errorEl) errorEl.textContent = 'Please enter username and password';
                return;
            }

            try {
                const response = await API.post('/auth/login', { username, password });
                State.token = response.token;
                State.user = { username };
                localStorage.setItem('argus_token', State.token);
                localStorage.setItem('argus_user', JSON.stringify(State.user));

                document.getElementById('userName').textContent = username;
                document.getElementById('userAvatar').textContent = username.charAt(0).toUpperCase();

                await this.loadInitialData();
                UI.showApp();
                WS.connect();
                this.startRefreshInterval();
                UI.toast('Welcome back, ' + username, 'success');
            } catch (error) {
                if (errorEl) errorEl.textContent = error.message || 'Login failed';
            }
        },

        logout() {
            State.token = null;
            State.user = null;
            State.agents = [];
            State.selectedAgent = null;
            localStorage.removeItem('argus_token');
            localStorage.removeItem('argus_user');
            WS.disconnect();
            this.stopRefreshInterval();
            UI.showLogin();
        },

        async loadInitialData() {
            const [agents, stats] = await Promise.all([
                API.get('/agents').catch(() => []),
                API.get('/dashboard/stats').catch(() => ({}))
            ]);

            State.agents = Array.isArray(agents) ? agents : [];
            State.stats = stats;

            UI.renderStats(stats);
            UI.renderAgentLists();

            if (State.user) {
                document.getElementById('userName').textContent = State.user.username;
                document.getElementById('userAvatar').textContent = State.user.username.charAt(0).toUpperCase();
            }
        },

        refreshInterval: null,

        startRefreshInterval() {
            this.refreshInterval = setInterval(() => {
                this.refreshStats();
            }, Config.REFRESH_INTERVAL);
        },

        stopRefreshInterval() {
            if (this.refreshInterval) {
                clearInterval(this.refreshInterval);
                this.refreshInterval = null;
            }
        },

        async refreshStats() {
            try {
                const stats = await API.get('/dashboard/stats');
                State.stats = stats;
                UI.renderStats(stats);
            } catch (error) {
                console.error('Stats refresh error:', error);
            }
        },

        async refreshAgents() {
            try {
                const agents = await API.get('/agents');
                State.agents = Array.isArray(agents) ? agents : [];
                UI.renderAgentLists();
                UI.toast('Agents refreshed', 'info');
            } catch (error) {
                UI.toast('Failed to refresh agents', 'error');
            }
        },

        navigateTo(view) {
            UI.navigateTo(view);
        },

        selectAgent(agentId) {
            State.selectedAgent = State.agents.find(a => a.id === agentId);
            UI.renderAgentLists();
        },

        selectAgentForTerminal(agentId) {
            const agent = State.agents.find(a => a.id === agentId);
            if (!agent) return;

            State.selectedAgent = agent;
            UI.renderTerminalAgents();
            
            document.getElementById('terminalTitle').textContent = agent.hostname;
            document.getElementById('terminalStatus').textContent = agent.status;
            UI.elements.terminalInput.disabled = false;
            document.getElementById('terminalSendBtn').disabled = false;

            UI.clearTerminal();
            UI.addTerminalLine(`Connected to ${agent.hostname} (${agent.id})`, 'system');
            UI.addTerminalLine(`OS: ${agent.os} ${agent.arch}`, 'system');
            UI.addTerminalLine('Type a command and press Enter', 'system');
        },

        selectAgentForFiles(agentId) {
            const agent = State.agents.find(a => a.id === agentId);
            if (!agent) return;

            State.selectedAgent = agent;
            UI.renderFilesAgents();
            this.loadFiles('/');
        },

        openTerminalFor(agentId) {
            this.navigateTo('terminal');
            setTimeout(() => this.selectAgentForTerminal(agentId), 100);
        },

        openFilesFor(agentId) {
            this.navigateTo('files');
            setTimeout(() => this.selectAgentForFiles(agentId), 100);
        },

        async executeCommand(command) {
            if (!State.selectedAgent) {
                UI.toast('Please select an agent first', 'warning');
                return;
            }

            if (!command.trim()) return;

            // Add to history
            State.commandHistory.unshift(command);
            if (State.commandHistory.length > 100) State.commandHistory.pop();
            State.commandHistoryIndex = -1;

            UI.addTerminalLine(`$ ${command}`, 'command');

            try {
                const response = await API.post(`/agents/${State.selectedAgent.id}/commands`, {
                    type: 'execute',
                    payload: { command },
                    timeout: 30
                });

                UI.addTerminalLine(`Command queued: ${response.command_id}`, 'system');
            } catch (error) {
                UI.addTerminalLine(`Error: ${error.message}`, 'error');
            }
        },

        async sendQuickCommand(type) {
            if (!State.selectedAgent) {
                UI.toast('Please select an agent first', 'warning');
                return;
            }

            UI.addTerminalLine(`> ${type}`, 'command');

            try {
                const response = await API.post(`/agents/${State.selectedAgent.id}/commands`, {
                    type: type,
                    payload: {},
                    timeout: 30
                });

                UI.addTerminalLine(`Command queued: ${response.command_id}`, 'system');
            } catch (error) {
                UI.addTerminalLine(`Error: ${error.message}`, 'error');
            }
        },

        clearTerminal() {
            UI.clearTerminal();
        },

        async loadFiles(path = '/') {
            if (!State.selectedAgent) {
                UI.toast('Please select an agent first', 'warning');
                return;
            }

            document.getElementById('filesPath').value = path;

            try {
                const files = await API.get(`/agents/${State.selectedAgent.id}/files?path=${encodeURIComponent(path)}`);
                this.renderFiles(files);
            } catch (error) {
                UI.toast('Failed to load files', 'error');
            }
        },

        renderFiles(files) {
            const container = document.getElementById('filesContainer');
            if (!container) return;

            if (!files || files.length === 0) {
                container.innerHTML = '<div class="empty-state"><p>No files found</p></div>';
                return;
            }

            container.innerHTML = `
                <div class="files-grid">
                    ${files.map(file => `
                        <div class="file-item ${file.is_dir ? 'folder' : ''}" 
                             onclick="Argus.handleFileClick('${file.path}', ${file.is_dir})">
                            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                ${file.is_dir 
                                    ? '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>'
                                    : '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>'
                                }
                            </svg>
                            <span>${UI.escape(file.name)}</span>
                        </div>
                    `).join('')}
                </div>
            `;
        },

        handleFileClick(path, isDir) {
            if (isDir) {
                this.loadFiles(path);
            } else {
                this.downloadFile(path);
            }
        },

        filesNavigateUp() {
            const path = document.getElementById('filesPath')?.value || '/';
            const parent = path.split('/').slice(0, -1).join('/') || '/';
            this.loadFiles(parent);
        },

        refreshFiles() {
            const path = document.getElementById('filesPath')?.value || '/';
            this.loadFiles(path);
        },

        async downloadFile(path) {
            if (!State.selectedAgent) return;

            try {
                await API.post(`/agents/${State.selectedAgent.id}/files/download`, { path });
                UI.toast('Download started', 'success');
            } catch (error) {
                UI.toast('Download failed', 'error');
            }
        },

        async loadTasks() {
            try {
                const tasks = await API.get('/tasks');
                this.renderTasks(tasks);
            } catch (error) {
                UI.toast('Failed to load tasks', 'error');
            }
        },

        renderTasks(tasks) {
            const container = document.getElementById('tasksList');
            if (!container) return;

            if (!tasks || tasks.length === 0) {
                container.innerHTML = '<div class="empty-state"><p>No scheduled tasks</p></div>';
                return;
            }

            container.innerHTML = tasks.map(task => `
                <div class="task-item">
                    <span class="task-status ${task.status}"></span>
                    <div class="task-info">
                        <h4>${UI.escape(task.name)}</h4>
                        <p>${UI.escape(task.command)}</p>
                    </div>
                    <div class="task-schedule">
                        <span class="schedule">${task.schedule || 'Manual'}</span>
                        <span class="next-run">Next: ${task.next_run ? UI.formatDate(task.next_run) : 'N/A'}</span>
                    </div>
                    <div class="task-actions">
                        <button class="btn btn-sm btn-secondary" onclick="Argus.runTask('${task.id}')">Run</button>
                        <button class="btn btn-sm btn-danger" onclick="Argus.deleteTask('${task.id}')">Delete</button>
                    </div>
                </div>
            `).join('');
        },

        async createTask() {
            const form = document.getElementById('newTaskForm');
            if (!form) return;

            const formData = new FormData(form);
            const data = Object.fromEntries(formData);

            try {
                await API.post('/tasks', data);
                UI.closeModal();
                this.loadTasks();
                UI.toast('Task created', 'success');
            } catch (error) {
                UI.toast('Failed to create task', 'error');
            }
        },

        async loadGroups() {
            try {
                const groups = await API.get('/groups');
                this.renderGroups(groups);
            } catch (error) {
                UI.toast('Failed to load groups', 'error');
            }
        },

        renderGroups(groups) {
            const container = document.getElementById('groupsGrid');
            if (!container) return;

            if (!groups || groups.length === 0) {
                container.innerHTML = '<div class="empty-state"><p>No groups created</p></div>';
                return;
            }

            container.innerHTML = groups.map(group => `
                <div class="group-card">
                    <div class="group-card-header">
                        <h4>${UI.escape(group.name)}</h4>
                        <span class="badge badge-primary">${group.agents?.length || 0} agents</span>
                    </div>
                    <div class="group-card-body">
                        <p>${UI.escape(group.description || 'No description')}</p>
                        <div class="group-agents">
                            ${(group.agents || []).slice(0, 5).map(a => 
                                `<span class="group-agent-tag">${a.hostname || a}</span>`
                            ).join('')}
                            ${(group.agents?.length || 0) > 5 ? `<span class="group-agent-tag">+${group.agents.length - 5} more</span>` : ''}
                        </div>
                    </div>
                    <div class="group-card-footer">
                        <button class="btn btn-sm btn-secondary" onclick="Argus.sendGroupCommand('${group.id}')">Send Command</button>
                        <button class="btn btn-sm btn-danger" onclick="Argus.deleteGroup('${group.id}')">Delete</button>
                    </div>
                </div>
            `).join('');
        },

        async createGroup() {
            const form = document.getElementById('newGroupForm');
            if (!form) return;

            const formData = new FormData(form);
            const data = {
                name: formData.get('name'),
                description: formData.get('description'),
                agents: formData.getAll('agents')
            };

            try {
                await API.post('/groups', data);
                UI.closeModal();
                this.loadGroups();
                UI.toast('Group created', 'success');
            } catch (error) {
                UI.toast('Failed to create group', 'error');
            }
        },

        async loadAuditLog() {
            try {
                const logs = await API.get('/audit');
                this.renderAuditLog(logs);
            } catch (error) {
                UI.toast('Failed to load audit log', 'error');
            }
        },

        renderAuditLog(logs) {
            const tbody = document.getElementById('auditTableBody');
            if (!tbody) return;

            if (!logs || logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center">No audit logs</td></tr>';
                return;
            }

            tbody.innerHTML = logs.map(log => `
                <tr>
                    <td>${UI.formatDate(log.timestamp)}</td>
                    <td>${UI.escape(log.user_id || 'System')}</td>
                    <td>${UI.escape(log.action)}</td>
                    <td>${UI.escape(log.resource)}</td>
                    <td><code>${log.ip_address}</code></td>
                    <td>
                        <span class="badge badge-${log.success ? 'success' : 'danger'}">
                            ${log.success ? 'Success' : 'Failed'}
                        </span>
                    </td>
                </tr>
            `).join('');
        },

        async loadSettings() {
            try {
                const users = await API.get('/users').catch(() => []);
                this.renderUsers(users);
            } catch (error) {
                console.error('Settings load error:', error);
            }
        },

        renderUsers(users) {
            const tbody = document.getElementById('usersTableBody');
            if (!tbody) return;

            if (!users || users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center">No users found</td></tr>';
                return;
            }

            tbody.innerHTML = users.map(user => `
                <tr>
                    <td>${UI.escape(user.username)}</td>
                    <td>${UI.escape(user.email)}</td>
                    <td><span class="badge badge-primary">${user.role}</span></td>
                    <td>${user.last_login ? UI.formatDate(user.last_login) : 'Never'}</td>
                    <td>
                        <button class="btn btn-sm btn-secondary" onclick="Argus.editUser('${user.id}')">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="Argus.showModal('confirmDelete', {type: 'user', id: '${user.id}', name: '${user.username}'})">Delete</button>
                    </td>
                </tr>
            `).join('');
        },

        async createUser() {
            const form = document.getElementById('newUserForm');
            if (!form) return;

            const formData = new FormData(form);
            const data = Object.fromEntries(formData);

            try {
                await API.post('/users', data);
                UI.closeModal();
                this.loadSettings();
                UI.toast('User created', 'success');
            } catch (error) {
                UI.toast('Failed to create user', 'error');
            }
        },

        showModal(type, data) {
            UI.showModal(type, data);
        },

        async disconnectAgent(agentId) {
            try {
                await API.delete(`/agents/${agentId}`);
                this.refreshAgents();
                UI.toast('Agent disconnected', 'success');
            } catch (error) {
                UI.toast('Failed to disconnect agent', 'error');
            }
        },

        broadcastCommand() {
            UI.toast('Broadcast feature coming soon', 'info');
        },

        exportAgents() {
            const data = JSON.stringify(State.agents, null, 2);
            this.downloadJson(data, 'agents.json');
        },

        exportAuditLog() {
            UI.toast('Export feature coming soon', 'info');
        },

        downloadJson(data, filename) {
            const blob = new Blob([data], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            URL.revokeObjectURL(url);
        },

        async uploadFile() {
            const form = document.getElementById('uploadFileForm');
            if (!form) return;

            const formData = new FormData(form);
            const agentId = formData.get('agent_id');

            if (!agentId) {
                UI.toast('Please select an agent', 'warning');
                return;
            }

            try {
                await fetch(`${Config.API_BASE}/agents/${agentId}/files/upload`, {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + State.token
                    },
                    body: formData
                });

                UI.closeModal();
                UI.toast('File uploaded successfully', 'success');
            } catch (error) {
                UI.toast('Upload failed', 'error');
            }
        },

        globalSearch(query) {
            if (!query.trim()) return;
            
            const results = State.agents.filter(a => 
                a.hostname.toLowerCase().includes(query.toLowerCase()) ||
                a.id.toLowerCase().includes(query.toLowerCase()) ||
                a.ip_address.includes(query)
            );

            if (results.length === 1) {
                this.navigateTo('agents');
                this.selectAgent(results[0].id);
            } else if (results.length > 0) {
                this.navigateTo('agents');
                document.getElementById('agentSearch').value = query;
                UI.filterAgents();
            } else {
                UI.toast('No results found', 'info');
            }
        }
    };

    // =========================================================================
    // Initialize
    // =========================================================================

    document.addEventListener('DOMContentLoaded', () => {
        Argus.init();
    });

    // Export to global scope
    window.Argus = Argus;
    window.UI = UI;

})();
