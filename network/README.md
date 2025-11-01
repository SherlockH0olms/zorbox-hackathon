# ZORBOX Network — Sinkhole, Monitor, IDS

## Quick start
1. Place certs into `/etc/nginx/certs/` (fake-cert.pem / fake-key.pem)
2. Start sinkhole container:
   docker run -d --name sinkhole --network analysis_net --ip 172.20.30.254 \
     -v $(pwd)/network/sinkhole-config.conf:/etc/nginx/nginx.conf:ro \
     -v /etc/nginx/certs:/etc/nginx/certs:ro nginx:alpine
3. Create log directory:
   sudo mkdir -p /var/log/zorbox/monitor_reports
   sudo chown $USER:$USER /var/log/zorbox -R
4. Run monitor:
   sudo ~/zorbox/network/monitor.py --job-id test_job_001
5. Load IDS rules into Suricata/Snort if used.
