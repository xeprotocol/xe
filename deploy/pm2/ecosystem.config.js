module.exports = {
  apps: [
    {
      name: 'xe-node',
      script: '/usr/local/bin/xe-node',
      args: [
        'node',
        '--port', '9000',
        '--api-port', '8080',
        '--api-bind', '127.0.0.1',
        '--metrics-addr', '127.0.0.1:9095',
        '--data', '/var/lib/xe',
        '--log-level', 'info',
        '--log-file', '/var/lib/xe/node.log',
        '--log-max-size', '64',
        '--log-max-files', '5',
      ],
      exec_mode: 'fork',
      autorestart: true,
      max_restarts: 100,
      restart_delay: 5000,
      out_file: '/var/log/xe/pm2-out.log',
      error_file: '/var/log/xe/pm2-err.log',
      max_memory_restart: '4G',
      env: {
      },
    },
  ],
};
