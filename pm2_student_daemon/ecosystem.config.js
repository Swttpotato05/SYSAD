/**
 * PM2 Ecosystem Configuration for Student Workstation Telemetry Daemon
 * 
 * Functions:
 * 1. Defines process name as 'StudentTelemetry'
 * 2. Launches script invisibly without showing a terminal window
 * 3. Enforces auto-restart on crashes with max memory restart limit
 * 4. Injects central server IP / Port configuration
 */

module.exports = {
  apps: [
    {
      name: "StudentTelemetry",
      script: "agent.js",
      cwd: __dirname,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "150M",
      env: {
        SYSAD_SERVER_HOST: process.env.SYSAD_SERVER_HOST || "127.0.0.1",
        SYSAD_SERVER_PORT: process.env.SYSAD_SERVER_PORT || "8000",
        STUDENT_USER: process.env.STUDENT_USER || "alex.student",
        NODE_ENV: "production"
      },
      error_file: "./logs/err.log",
      out_file: "./logs/out.log",
      log_file: "./logs/combined.log",
      time: true
    }
  ]
};

