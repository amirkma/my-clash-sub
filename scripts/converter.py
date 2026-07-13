import requests
import yaml
import json
import os
import base64
import urllib.parse
from datetime import datetime

# لینک‌های کانفیگ
CONFIG_URLS = {
    "mixed": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/mixed-all.txt",
    "lite": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/mixed-light-all.txt",
    "vmess": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/vmess-all.txt",
    "vless": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/vless-all.txt",
    "trojan": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/trojan-all.txt",
    "ss": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/ss-all.txt"
}

def parse_vmess(url):
    """پارس کردن لینک VMESS"""
    try:
        encoded = url.replace('vmess://', '')
        # اضافه کردن padding اگر نیاز باشد
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += '=' * (4 - missing_padding)
        
        decoded = base64.b64decode(encoded).decode('utf-8')
        data = json.loads(decoded)
        
        proxy = {
            "name": data.get("ps", f"VMESS-{data.get('add', 'unknown')}"),
            "type": "vmess",
            "server": data.get("add", ""),
            "port": int(data.get("port", 443)),
            "uuid": data.get("id", ""),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
            "udp": True
        }
        
        # تنظیمات TLS - به صورت بولین (true/false)
        tls = data.get("tls", "")
        if tls == "tls" or tls == "true":
            proxy["tls"] = True
        else:
            proxy["tls"] = False
        
        # تنظیمات Network
        network = data.get("net", "tcp")
        proxy["network"] = network
        
        # تنظیمات WS
        if network == "ws":
            proxy["ws-path"] = data.get("path", "/")
            host = data.get("host", "")
            if host:
                proxy["ws-headers"] = {
                    "Host": host
                }
        
        # تنظیمات GRPC
        if network == "grpc":
            proxy["grpc-service-name"] = data.get("path", "")
        
        # تنظیمات HTTP
        if network == "http":
            proxy["http-opts"] = {
                "method": "GET",
                "path": [data.get("path", "/")]
            }
            host = data.get("host", "")
            if host:
                proxy["http-opts"]["headers"] = {
                    "Host": [host]
                }
        
        # تنظیمات H2
        if network == "h2":
            proxy["h2-opts"] = {
                "host": [data.get("host", "")]
            }
            proxy["h2-opts"]["path"] = data.get("path", "/")
        
        # تنظیمات QUIC
        if network == "quic":
            proxy["quic-opts"] = {
                "method": "CHACHA20-POLY1305",
                "key": data.get("id", ""),
                "security": "none"
            }
        
        # تنظیمات Reality
        if data.get("flow", "") == "xtls-rprx-vision":
            proxy["flow"] = "xtls-rprx-vision"
        
        return proxy
    except Exception as e:
        print(f"⚠️ خطا در پارس VMESS: {e}")
        return None

def parse_vless(url):
    """پارس کردن لینک VLESS"""
    try:
        # حذف vless://
        url = url.replace('vless://', '')
        
        # جداسازی UUID و بقیه
        if '@' not in url:
            return None
        
        uuid, rest = url.split('@', 1)
        
        # جداسازی server:port و پارامترها
        if '?' not in rest:
            server_port = rest
            params = ''
        else:
            server_port, params = rest.split('?', 1)
        
        server, port = server_port.split(':', 1)
        port = int(port)
        
        # پارس کردن پارامترها
        param_dict = {}
        if params:
            for param in params.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    param_dict[key] = urllib.parse.unquote(value)
        
        # ساخت پروکسی
        proxy = {
            "name": param_dict.get("remark", f"VLESS-{server}"),
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "udp": True
        }
        
        # تنظیمات TLS - بولین
        security = param_dict.get("security", "")
        if security == "tls" or security == "reality":
            proxy["tls"] = True
            if security == "reality":
                proxy["flow"] = "xtls-rprx-vision"
        else:
            proxy["tls"] = False
        
        # تنظیمات Network
        network = param_dict.get("type", "tcp")
        proxy["network"] = network
        
        # تنظیمات WS
        if network == "ws":
            proxy["ws-path"] = param_dict.get("path", "/")
            host = param_dict.get("host", "")
            if host:
                proxy["ws-headers"] = {
                    "Host": host
                }
        
        # تنظیمات GRPC
        if network == "grpc":
            proxy["grpc-service-name"] = param_dict.get("serviceName", "")
        
        # تنظیمات Reality
        if security == "reality":
            proxy["reality-opts"] = {
                "public-key": param_dict.get("pbk", ""),
                "short-id": param_dict.get("sid", "")
            }
            if param_dict.get("fp", ""):
                proxy["reality-opts"]["fingerprint"] = param_dict.get("fp", "")
        
        # تنظیمات Flow
        if param_dict.get("flow", ""):
            proxy["flow"] = param_dict.get("flow", "")
        
        # تنظیمات SNI
        if param_dict.get("sni", ""):
            proxy["sni"] = param_dict.get("sni", "")
        
        return proxy
    except Exception as e:
        print(f"⚠️ خطا در پارس VLESS: {e}")
        return None

def parse_trojan(url):
    """پارس کردن لینک TROJAN"""
    try:
        # حذف trojan://
        url = url.replace('trojan://', '')
        
        if '@' not in url:
            return None
        
        password, rest = url.split('@', 1)
        
        if '?' not in rest:
            server_port = rest
            params = ''
        else:
            server_port, params = rest.split('?', 1)
        
        server, port = server_port.split(':', 1)
        port = int(port)
        
        param_dict = {}
        if params:
            for param in params.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    param_dict[key] = urllib.parse.unquote(value)
        
        proxy = {
            "name": param_dict.get("remark", f"TROJAN-{server}"),
            "type": "trojan",
            "server": server,
            "port": port,
            "password": password,
            "udp": True
        }
        
        # تنظیمات TLS - بولین
        tls = param_dict.get("tls", "")
        if tls == "1" or tls == "true" or tls == "tls":
            proxy["tls"] = True
        else:
            proxy["tls"] = False
        
        # تنظیمات SNI
        if param_dict.get("sni", ""):
            proxy["sni"] = param_dict.get("sni", "")
        
        # تنظیمات ALPN
        if param_dict.get("alpn", ""):
            proxy["alpn"] = param_dict.get("alpn", "").split(',')
        
        # تنظیمات Skip Cert Verify
        allow_insecure = param_dict.get("allowInsecure", "")
        if allow_insecure == "1" or allow_insecure == "true":
            proxy["skip-cert-verify"] = True
        else:
            proxy["skip-cert-verify"] = False
        
        return proxy
    except Exception as e:
        print(f"⚠️ خطا در پارس TROJAN: {e}")
        return None

def parse_ss(url):
    """پارس کردن لینک Shadowsocks"""
    try:
        # حذف ss://
        url = url.replace('ss://', '')
        
        # اگر لینک با @ باشد
        if '@' in url:
            # فرمت: method:password@server:port
            method_pass, rest = url.split('@', 1)
            method, password = method_pass.split(':', 1)
            server, port = rest.split(':', 1)
            port = int(port)
        else:
            # فرمت base64
            # اضافه کردن padding
            missing_padding = len(url) % 4
            if missing_padding:
                url += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(url).decode('utf-8')
            method_pass, server_port = decoded.split('@', 1)
            method, password = method_pass.split(':', 1)
            server, port = server_port.split(':', 1)
            port = int(port)
        
        proxy = {
            "name": f"SS-{server}",
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
            "udp": True
        }
        
        return proxy
    except Exception as e:
        print(f"⚠️ خطا در پارس SS: {e}")
        return None

def parse_config_line(line):
    """تشخیص نوع لینک و پارس کردن آن"""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    try:
        if line.startswith('vmess://'):
            return parse_vmess(line)
        elif line.startswith('vless://'):
            return parse_vless(line)
        elif line.startswith('trojan://'):
            return parse_trojan(line)
        elif line.startswith('ss://'):
            return parse_ss(line)
        else:
            return None
    except Exception as e:
        print(f"⚠️ خطا در پردازش خط: {e}")
        return None

def create_clash_config(proxies, config_name):
    """ایجاد کانفیگ استاندارد Clash"""
    
    # محدود کردن تعداد پروکسی‌ها
    max_proxies = 100
    if len(proxies) > max_proxies:
        proxies = proxies[:max_proxies]
    
    # ساختار پایه Clash
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": [p["name"] for p in proxies]
            },
            {
                "name": "Auto",
                "type": "url-test",
                "proxies": [p["name"] for p in proxies],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            },
            {
                "name": "Fallback",
                "type": "fallback",
                "proxies": [p["name"] for p in proxies],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            },
            {
                "name": "LoadBalance",
                "type": "load-balance",
                "proxies": [p["name"] for p in proxies],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "strategy": "consistent-hashing"
            }
        ],
        "rules": [
            "MATCH,PROXY"
        ]
    }
    
    return config

def main():
    """تابع اصلی"""
    print("🚀 شروع فرآیند تبدیل کانفیگ‌ها به فرمت Clash...")
    
    # ایجاد پوشه output
    os.makedirs("output", exist_ok=True)
    
    # دریافت و پردازش هر کانفیگ
    for name, url in CONFIG_URLS.items():
        print(f"\n📥 دریافت {name} از {url}")
        
        try:
            response = requests.get(url, timeout=30)
            if response.status_code != 200:
                print(f"❌ خطا در دریافت {name}: {response.status_code}")
                continue
            
            lines = response.text.split('\n')
            proxies = []
            success_count = 0
            
            for line in lines:
                proxy = parse_config_line(line)
                if proxy:
                    proxies.append(proxy)
                    success_count += 1
            
            print(f"✅ {success_count} پروکسی معتبر از {len(lines)} خط دریافت شد")
            
            if proxies:
                # ایجاد کانفیگ کامل
                config = create_clash_config(proxies, name)
                
                # ذخیره فایل اصلی
                output_file = f"output/{name}.yaml"
                with open(output_file, 'w', encoding='utf-8') as f:
                    yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
                print(f"✅ فایل {output_file} ایجاد شد")
                
                # ایجاد نسخه لایت (50 پروکسی اول)
                if len(proxies) > 50:
                    lite_proxies = proxies[:50]
                    lite_config = create_clash_config(lite_proxies, f"{name}-lite")
                    output_file_lite = f"output/{name}-lite.yaml"
                    with open(output_file_lite, 'w', encoding='utf-8') as f:
                        yaml.dump(lite_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
                    print(f"✅ فایل {output_file_lite} ایجاد شد (نسخه لایت)")
                
                # ایجاد نسخه بسیار سبک (20 پروکسی اول)
                if len(proxies) > 20:
                    mini_proxies = proxies[:20]
                    mini_config = create_clash_config(mini_proxies, f"{name}-mini")
                    output_file_mini = f"output/{name}-mini.yaml"
                    with open(output_file_mini, 'w', encoding='utf-8') as f:
                        yaml.dump(mini_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
                    print(f"✅ فایل {output_file_mini} ایجاد شد (نسخه مینی)")
            else:
                print(f"❌ هیچ پروکسی معتبری برای {name} یافت نشد")
                
        except Exception as e:
            print(f"❌ خطا در پردازش {name}: {str(e)}")
    
    print("\n🎉 فرآیند تبدیل با موفقیت به پایان رسید!")
    print("📁 فایل‌های خروجی در پوشه output/ قرار دارند")

if __name__ == "__main__":
    main()
