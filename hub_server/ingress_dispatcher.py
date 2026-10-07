#!/usr/bin/env python3
"""
GAVASAH Autonomous Dynamic Ingress Dispatcher
Routes wildcard subdomain HTTP/WebSocket connections to client reverse tunnels.
Provides high-security access suspension enforcement and branded contact prompt.
"""
import asyncio
import sqlite3
import time
import os
import html

DB_PATH = '/srv/gavasah-cloud/fleet.db'

SUSPENSION_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Remote Access Disabled | GAVASAH Cloud Security</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: #060913;
            color: #f1f5f9;
            font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        .suspension-card {{
            background: radial-gradient(circle at top right, rgba(239, 68, 68, 0.12), transparent 50%),
                        linear-gradient(180deg, #0e172a 0%, #090e1b 100%);
            border: 1px solid rgba(239, 68, 68, 0.35);
            border-radius: 20px;
            max-width: 520px;
            width: 100%;
            padding: 44px 36px;
            text-align: center;
            box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.7), 0 0 35px rgba(239, 68, 68, 0.15);
        }}
        .icon-halo {{
            width: 76px;
            height: 76px;
            margin: 0 auto 22px;
            border-radius: 50%;
            background: rgba(239, 68, 68, 0.15);
            border: 2px solid rgba(239, 68, 68, 0.4);
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 30px rgba(239, 68, 68, 0.25);
        }}
        .icon-halo svg {{
            width: 38px;
            height: 38px;
            stroke: #ef4444;
        }}
        .badge-status {{
            display: inline-block;
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.4);
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 1.2px;
            padding: 6px 14px;
            border-radius: 9999px;
            text-transform: uppercase;
            margin-bottom: 16px;
        }}
        h1 {{
            font-size: 23px;
            font-weight: 800;
            color: #ffffff;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }}
        .gateway-tag {{
            font-size: 13px;
            color: #94a3b8;
            margin-bottom: 20px;
            font-family: monospace;
            background: rgba(15, 23, 42, 0.6);
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }}
        p {{
            font-size: 14px;
            line-height: 1.6;
            color: #94a3b8;
            margin-bottom: 24px;
        }}
        .contact-box {{
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 14px;
            padding: 18px 20px;
            margin-bottom: 26px;
            text-align: left;
        }}
        .contact-title {{
            font-size: 11px;
            font-weight: 700;
            color: #cbd5e1;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .contact-instruction {{
            font-size: 13.5px;
            color: #e2e8f0;
            line-height: 1.55;
        }}
        .footer-note {{
            font-size: 12px;
            color: #64748b;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }}
    </style>
    <script>
        // Aggressively unregister all Service Workers and clear caches from previously saved sessions
        if ('serviceWorker' in navigator) {{
            navigator.serviceWorker.getRegistrations().then(function(regs) {{
                for (var r of regs) {{ r.unregister(); }}
            }});
        }}
        if ('caches' in window) {{
            caches.keys().then(function(names) {{
                for (var name of names) {{ caches.delete(name); }}
            }});
        }}
        try {{
            sessionStorage.clear();
            localStorage.clear();
        }} catch(e) {{}}
    </script>
</head>
<body>
    <div class="suspension-card">
        <div class="icon-halo">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
        </div>
        <div class="badge-status">Remote Access Disabled</div>
        <h1>Remote Access Suspended</h1>
        <div class="gateway-tag">{client_display}</div>
        <p>
            Remote client access to this Home Assistant gateway has been disabled by the system administrator.
        </p>
        <div class="contact-box">
            <div class="contact-title">
                <span>📞 Next Steps</span>
            </div>
            <div class="contact-instruction">
                Please contact your <strong>Authorized Dealer ({dealer_name})</strong> or <strong>Manufacturer</strong> to restore remote access.
            </div>
        </div>
        <div class="footer-note">
            <span>🛡️</span> GAVASAH Cloud Security Platform
        </div>
    </div>
</body>
</html>"""

OFFLINE_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gateway Offline | GAVASAH Cloud</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: #060913;
            color: #f1f5f9;
            font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        .card {{
            background: radial-gradient(circle at top right, rgba(245, 158, 11, 0.12), transparent 50%),
                        linear-gradient(180deg, #0e172a 0%, #090e1b 100%);
            border: 1px solid rgba(245, 158, 11, 0.35);
            border-radius: 20px;
            max-width: 520px;
            width: 100%;
            padding: 44px 36px;
            text-align: center;
            box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.7);
        }}
        .icon-halo {{
            width: 76px;
            height: 76px;
            margin: 0 auto 22px;
            border-radius: 50%;
            background: rgba(245, 158, 11, 0.15);
            border: 2px solid rgba(245, 158, 11, 0.4);
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .icon-halo svg {{ width: 38px; height: 38px; stroke: #f59e0b; }}
        .badge-status {{
            display: inline-block;
            background: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.4);
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 1.2px;
            padding: 6px 14px;
            border-radius: 9999px;
            text-transform: uppercase;
            margin-bottom: 16px;
        }}
        h1 {{ font-size: 23px; font-weight: 800; color: #ffffff; margin-bottom: 12px; }}
        p {{ font-size: 14px; line-height: 1.6; color: #94a3b8; margin-bottom: 24px; }}
        .note {{ background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 18px 20px; font-size: 13.5px; color: #e2e8f0; line-height: 1.55; text-align: left; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon-halo">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path>
                <line x1="12" y1="2" x2="12" y2="12"></line>
            </svg>
        </div>
        <div class="badge-status">Gateway Offline</div>
        <h1>Target Gateway Offline</h1>
        <p>The Home Assistant instance is currently unreachable or the secure reverse tunnel is reconnecting.</p>
        <div class="note">
            Please check that the local gateway hardware is powered on and connected to the internet. If you recently restarted the gateway, please wait 30 seconds and refresh.
        </div>
    </div>
</body>
</html>"""

def get_client_info(slug):
    """Fetches real-time client status directly from SQLite WAL database."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            "SELECT client_id, name, dealer_name, dashboard_port, remote_enabled "
            "FROM clients WHERE client_id = ? OR domain = ?",
            (slug, f"{slug}.gavasah.com")
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            return {'status': 'NOT_FOUND', 'slug': slug}

        is_enabled = bool(row['remote_enabled'])
        if not is_enabled:
            return {
                'status': 'SUSPENDED',
                'client_id': row['client_id'],
                'name': row['name'] or row['client_id'],
                'dealer_name': row['dealer_name'] or 'Authorized Dealer',
                'port': None
            }

        port = int(row['dashboard_port']) if row['dashboard_port'] else None
        return {
            'status': 'ACTIVE',
            'client_id': row['client_id'],
            'name': row['name'] or row['client_id'],
            'dealer_name': row['dealer_name'] or 'Authorized Dealer',
            'port': port
        }
    except Exception as e:
        print(f"[!] Dispatcher DB lookup error for {slug}: {e}", flush=True)
        return {'status': 'ERROR', 'error': str(e), 'slug': slug}

def build_http_response(status_code, status_text, body_html, clear_site_data=False):
    crlf = b"\r\n"
    body_bytes = body_html.encode('utf-8')
    headers = [
        f"HTTP/1.1 {status_code} {status_text}".encode('ascii'),
        b"Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body_bytes)}".encode('ascii'),
        b"Connection: close",
        b"Cache-Control: no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0",
        b"Pragma: no-cache",
        b"Expires: 0"
    ]
    if clear_site_data:
        headers.append(b'Clear-Site-Data: "cache", "cookies", "storage", "executionContexts"')
    
    header_block = crlf.join(headers) + crlf + crlf
    return header_block + body_bytes

async def handle_connection(reader, writer):
    try:
        initial_data = await reader.read(4096)
        if not initial_data:
            writer.close()
            return

        lines = initial_data.split(bytes([13, 10]))
        slug = None
        for l in lines:
            if l.lower().startswith(b"host:"):
                host_str = l[5:].decode('ascii', errors='ignore').strip()
                if ':' in host_str:
                    host_str = host_str.split(':')[0]
                slug = host_str[:-len('.gavasah.com')] if host_str.endswith('.gavasah.com') else host_str
                break

        if not slug:
            writer.close()
            return

        client_info = get_client_info(slug)
        status = client_info.get('status')

        # 1. Suspended / Remote Access Disabled
        if status == 'SUSPENDED':
            client_display = html.escape(client_info.get('name', slug))
            dealer_name = html.escape(client_info.get('dealer_name', 'Authorized Dealer'))
            resp_html = SUSPENSION_HTML_TEMPLATE.format(
                client_display=client_display,
                dealer_name=dealer_name
            )
            resp = build_http_response(403, "Forbidden", resp_html, clear_site_data=True)
            writer.write(resp)
            await writer.drain()
            writer.close()
            return

        # 2. Not Registered
        if status in ['NOT_FOUND', 'ERROR']:
            resp_html = f"""<!DOCTYPE html><html><body style="background:#060913;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;"><div style="text-align:center;max-width:480px;padding:30px;"><h2 style="color:#ef4444;">Gateway Not Found</h2><p style="color:#94a3b8;line-height:1.6;">Gateway <code>{html.escape(slug)}</code> is not registered on GAVASAH Cloud.<br><br>Please contact your Authorized Dealer or Manufacturer.</p></div></body></html>"""
            resp = build_http_response(404, "Not Found", resp_html, clear_site_data=True)
            writer.write(resp)
            await writer.drain()
            writer.close()
            return

        # 3. Active - Forward to target reverse tunnel port
        target_port = client_info.get('port')
        if not target_port:
            resp_html = OFFLINE_HTML_TEMPLATE
            resp = build_http_response(502, "Bad Gateway", resp_html)
            writer.write(resp)
            await writer.drain()
            writer.close()
            return

        try:
            up_reader, up_writer = await asyncio.open_connection('127.0.0.1', target_port)
        except Exception:
            resp_html = OFFLINE_HTML_TEMPLATE
            resp = build_http_response(503, "Service Unavailable", resp_html)
            writer.write(resp)
            await writer.drain()
            writer.close()
            return

        up_writer.write(initial_data)
        await up_writer.drain()

        async def pipe(src, dst):
            try:
                while True:
                    buf = await src.read(65536)
                    if not buf:
                        break
                    dst.write(buf)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try: dst.close()
                except: pass

        await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
    except Exception:
        pass
    finally:
        try: writer.close()
        except: pass

async def main():
    server = await asyncio.start_server(handle_connection, '0.0.0.0', 10000)
    print("[*] GAVASAH Autonomous Dynamic Ingress Dispatcher active on port 10000...", flush=True)
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
