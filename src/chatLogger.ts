export interface LogEntry {
    timestamp: number;
    level: 'debug' | 'info' | 'warn' | 'error';
    message: string;
    data?: any;
}

export class ChatLogger {
    private logs: LogEntry[] = [];
    private maxLogs = 1000; // Keep last 1000 logs

    log(level: LogEntry['level'], message: string, data?: any) {
        const entry: LogEntry = {
            timestamp: Date.now(),
            level,
            message,
            data
        };

        this.logs.push(entry);

        // Keep only the last maxLogs entries
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(-this.maxLogs);
        }

        // Also log to console for debugging
        console.log(`[${level.toUpperCase()}] ${message}`, data || '');
    }

    getLogs(): LogEntry[] {
        return [...this.logs];
    }

    getLogsByLevel(level: LogEntry['level']): LogEntry[] {
        return this.logs.filter(log => log.level === level);
    }

    getRecentLogs(count: number = 50): LogEntry[] {
        return this.logs.slice(-count);
    }

    clearLogs() {
        this.logs = [];
    }

    exportLogs(): string {
        return JSON.stringify(this.logs, null, 2);
    }

    logChatMessage(userMessage: string, agentResponse?: string) {
        this.log('info', 'Chat Message', {
            userMessage,
            agentResponse,
            timestamp: new Date().toISOString()
        });
    }

    logChatAction(action: string, details?: any) {
        this.log('debug', `Chat Action: ${action}`, details);
    }

    logError(error: string, context?: any) {
        this.log('error', error, context);
    }
} 