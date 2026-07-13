import requests
import yaml
import json
import os
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

def fetch_configs():
    """دریافت کانفیگ‌ها از لینک‌های raw"""
    configs = {}
    for name, url in CONFIG_URLS.items():
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                configs[name] = response.text
                print(f"✅ دریافت {name} با موفقیت")
            else:
                print(f"❌ خطا در دریافت {name}: {response.status_code}")
        except Exception as e:
            print(f"❌ خطا در دریافت {name}: {str(e)}")
    return configs

def convert_to_clash_format(config_data):
    """تبدیل کانفیگ‌ها به فرمت Clash YML"""
    
    # ساختار پایه Clash
    clash_config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": [],
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": []
            }
        ],
        "rules": [
            "MATCH,PROXY"
        ]
    }
    
    # پردازش کانفیگ‌ها
    proxies = []
    lines = config_data.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        try:
            # تشخیص نوع پروکسی
            if line.startswith('vmess://'):
                proxy = parse_vmess(line)
            elif line.startswith('vless://'):
                proxy = parse_vless(line)
            elif line.startswith('trojan://'):
                proxy = parse_trojan(line)
            elif line.startswith('ss://'):
                proxy = parse_ss(line)
            else:
                continue
                
            if proxy:
                proxies.append(proxy)
        except Exception as e:
            print(f"⚠️ خطا در پردازش خط: {e}")
            continue
    
    clash_config["proxies"] = proxies
    clash_config["proxy-groups"][0]["proxies"] = [p["name"] for p in proxies[:50]]  # حداکثر 50 تا
    
    return clash_config

def parse_vmess(line):
    """پارس کردن لینک vmess"""
    import base64
    import json
    
    try:
        encoded = line.replace('vmess://', '')
        decoded = base64.b64decode(encoded).decode('utf-8')
        data = json.loads(decoded)
        
        return {
            "name": data.get("ps", "vmess-proxy"),
            "type": "vmess",
            "server": data.get("add", ""),
            "port": int(data.get("port", 443)),
            "uuid": data.get("id", ""),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
            "tls": data.get("tls", ""),
            "network": data.get("net", "tcp"),
            "ws-path": data.get("path", ""),
            "ws-headers": {"Host": data.get("host", "")}
        }
    except:
        return None

def parse_vless(line):
    """پارس کردن لینک vless"""
    import urllib.parse
    
    try:
        encoded = line.replace('vless://', '')
        parts = encoded.split('@')
        if len(parts) != 2:
            return None
            
        uuid = parts[0]
        server_part = parts[1].split('?')[0]
        server, port = server_part.split(':')
        
        query = parts[1].split('?')[1] if '?' in parts[1] else ''
        params = urllib.parse.parse_qs(query)
        
        return {
            "name": params.get('remark', ['vless-proxy'])[0],
            "type": "vless",
            "server": server,
            "port": int(port),
            "uuid": uuid,
            "tls": "tls" in params.get('security', []),
            "network": params.get('type', ['tcp'])[0],
            "ws-path": params.get('path', [''])[0],
            "ws-headers": {"Host": params.get('host', [''])[0]} if params.get('host') else {}
        }
    except:
        return None

def parse_trojan(line):
    """پارس کردن لینک trojan"""
    import urllib.parse
    
    try:
        encoded = line.replace('trojan://', '')
        parts = encoded.split('@')
        if len(parts) != 2:
            return None
            
        password = parts[0]
        server_part = parts[1].split('?')[0]
        server, port = server_part.split(':')
        
        query = parts[1].split('?')[1] if '?' in parts[1] else ''
        params = urllib.parse.parse_qs(query)
        
        return {
            "name": params.get('remark', ['trojan-proxy'])[0],
            "type": "trojan",
            "server": server,
            "port": int(port),
            "password": password,
            "sni": params.get('sni', [''])[0] if params.get('sni') else '',
            "skip-cert-verify": True
        }
    except:
        return None

def parse_ss(line):
    """پارس کردن لینک ss"""
    import base64
    
    try:
        encoded = line.replace('ss://', '')
        if '@' in encoded:
            # فرمت: method:password@server:port
            method_pass, rest = encoded.split('@')
            method, password = method_pass.split(':')
            server, port = rest.split(':')
        else:
            # فرمت base64
            decoded = base64.b64decode(encoded).decode('utf-8')
            method_pass, server_port = decoded.split('@')
            method, password = method_pass.split(':')
            server, port = server_port.split(':')
            
        return {
            "name": f"ss-{server}",
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": method,
            "password": password
        }
    except:
        return None

def main():
    """تابع اصلی"""
    print("🚀 شروع فرآیند تبدیل کانفیگ‌ها...")
    
    # ایجاد پوشه output اگر وجود ندارد
    os.makedirs("output", exist_ok=True)
    
    # دریافت کانفیگ‌ها
    configs = fetch_configs()
    
    # تبدیل هر کانفیگ
    for name, data in configs.items():
        if data:
            try:
                clash_config = convert_to_clash_format(data)
                
                # ذخیره فایل YML
                output_file = f"output/{name}.yml"
                with open(output_file, 'w', encoding='utf-8') as f:
                    yaml.dump(clash_config, f, allow_unicode=True, default_flow_style=False)
                
                print(f"✅ فایل {output_file} با موفقیت ایجاد شد")
                
                # ایجاد نسخه لایت (فقط 20 تا پروکسی)
                clash_config["proxy-groups"][0]["proxies"] = clash_config["proxy-groups"][0]["proxies"][:20]
                output_file_lite = f"output/{name}-lite.yml"
                with open(output_file_lite, 'w', encoding='utf-8') as f:
                    yaml.dump(clash_config, f, allow_unicode=True, default_flow_style=False)
                
                print(f"✅ فایل {output_file_lite} با موفقیت ایجاد شد")
                
            except Exception as e:
                print(f"❌ خطا در تبدیل {name}: {str(e)}")
    
    print("🎉 فرآیند تبدیل با موفقیت به پایان رسید!")

if __name__ == "__main__":
    main()
