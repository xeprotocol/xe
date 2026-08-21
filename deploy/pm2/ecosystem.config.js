// pm2 configuration for the xe bootstrap nodes (#841).
//
//   pm2 start deploy/pm2/ecosystem.config.js
//   pm2 save
//
// pm2 does not rotate logs on its own. Two options, and you want one of them:
//
//   1. Let the node do it (preferred — the bound holds regardless of pm2):
//        --log-file /var/lib/xe/node.log --log-max-size 64 --log-max-files 5
//      pm2's own out/err files then stay nearly empty.
//   2. Install pm2-logrotate:
//        pm2 install pm2-logrotate
//        pm2 set pm2-logrotate:max_size 64M
//        pm2 set pm2-logrotate:retain 5
//
// Doing neither is how a node fills a disk. This project has already lost a
// week of node authentication to exactly that.

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
        // Operator listener: /metrics, /health, /ready. Loopback by default;
        // /metrics is an unauthenticated firehose of network-wide state and
        // must not be exposed publicly.
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
      // With --log-file set, the node writes its own bounded file and these
      // stay small. They are still capped so a startup crash loop printing to
      // stderr cannot grow without limit.
      out_file: '/var/log/xe/pm2-out.log',
      error_file: '/var/log/xe/pm2-err.log',
      max_memory_restart: '4G',
      env: {
        // XE_API_ADMIN_TOKEN: '',  // gates POST /lease/request; disabled without it
      },
    },
  ],
};
