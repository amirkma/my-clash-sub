import requests
import yaml
import json
import os
import base64
import urllib.parse
from datetime import datetime
import re

# لینک‌های کانفیگ
CONFIG_URLS = {
    "mixed": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/mixed-all.txt",
    "lite": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/mixed-light-all.txt",
    "vmess": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/vmess-all.txt",
    "vless": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/vless-all.txt",
    "trojan": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/trojan-all.txt",
    "ss": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/ss-all.txt"
}

def safe_bool(value):
    """تبدیل ایمن به بولین"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ['true', '1', 't', 'yes', 'y', 'tls']
    return bool(value)

def safe_int(value, default=0):
    """تبدیل ایمن به عدد"""
    try:
        return int(value)
    except:
        return default

def clean_short_id(sid):
    """پاکسازی و اعتبارسنجی short-id برای Reality"""
    if not sid:
        return None
    # فقط کاراکترهای مجاز (اعداد و حروف کوچک)
    cleaned = re.sub(r'[^a-f0-9]', '', str(sid).lower())
    # باید بین 2 تا 8 کاراکتر باشد
    if len(cleaned) < 2 or len(cleaned) > 8:
        return None
    return cleaned

def parse_vmess(url):
    """پارس کردن لینک VMESS"""
    try:
        encoded = url.replace('vmess://', '')
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += '=' * (4 - missing_padding)
        
        decoded = base64.b64decode(encoded).decode('utf-8')
        data = json.loads(decoded)
        
        proxy = {
            "name": data.get("ps", f"VMESS-{data.get('add', 'unknown')}"),
            "type": "vmess",
            "server": data.get("add", ""),
            "port": safe_int(data.get("port", 443)),
            "uuid": data.get("id", ""),
            "alterId": safe_int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
            "udp": True
        }
        
        # TLS - بولین
        tls = data.get("tls", "")
        proxy["tls"] = safe_bool(tls)
        
        # Network
        network = data.get("net", "tcp")
        proxy["network"] = network
        
        # WS
        if network == "ws":
            path = data.get("path", "")
            if path:
                proxy["ws-path"] = path
            host = data.get("host", "")
            if host:
                proxy["ws-headers"] = {"Host": host}
        
        # GRPC
        if network == "grpc":
            path = data.get("path", "")
            if path:
                proxy["grpc-service-name"] = path
        
        # Skip Cert Verify
        if data.get("allowInsecure", "") == "1":
            proxy["skip-cert-verify"] = True
        
        return proxy
    except Exception as e:
        return None

def parse_vless(url):
    """پارس کردن لینک VLESS"""
    try:
        url = url.replace('vless://', '')
        
        if '@' not in url:
            return None
        
        uuid, rest = url.split('@', 1)
        
        if '?' not in rest:
            server_port = rest
            params = ''
        else:
            server_port, params = rest.split('?', 1)
        
        server, port = server_port.split(':', 1)
        port = safe_int(port, 443)
        
        param_dict = {}
        if params:
            for param in params.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    param_dict[key] = urllib.parse.unquote(value)
        
        proxy = {
            "name": param_dict.get("remark", f"VLESS-{server}"),
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "udp": True
        }
        
        # TLS - بولین
        security = param_dict.get("security", "")
        proxy["tls"] = safe_bool(security)
        
        # Network
        network = param_dict.get("type", "tcp")
        proxy["network"] = network
        
        # WS
        if network == "ws":
            path = param_dict.get("path", "")
            if path:
                proxy["ws-path"] = path
            host = param_dict.get("host", "")
            if host:
                proxy["ws-headers"] = {"Host": host}
        
        # GRPC
        if network == "grpc":
            service_name = param_dict.get("serviceName", "")
            if service_name:
                proxy["grpc-service-name"] = service_name
        
        # Reality
        if security == "reality":
            proxy["flow"] = param_dict.get("flow", "xtls-rprx-vision")
            
            # Reality opts
            reality_opts = {}
            
            # Public Key
            pbk = param_dict.get("pbk", "")
            if pbk:
                reality_opts["public-key"] = pbk
            
            # Short ID - با اعتبارسنجی
            sid = param_dict.get("sid", "")
            if sid:
                cleaned_sid = clean_short_id(sid)
                if cleaned_sid:
                    reality_opts["short-id"] = cleaned_sid
                # اگر cleaned_sid None باشه، نمی‌فرستیمش
            
            # Fingerprint
            fp = param_dict.get("fp", "")
            if fp:
                reality_opts["fingerprint"] = fp
            
            # فقط اگر reality_opts خالی نباشه اضافه کن
            if reality_opts:
                proxy["reality-opts"] = reality_opts
        
        # SNI
        sni = param_dict.get("sni", "")
        if sni:
            proxy["sni"] = sni
        
        # Flow (برای غیر Reality)
        if security != "reality":
            flow = param_dict.get("flow", "")
            if flow:
                proxy["flow"] = flow
        
        # Skip Cert Verify
        allow_insecure = param_dict.get("allowInsecure", "")
        if allow_insecure:
            proxy["skip-cert-verify"] = safe_bool(allow_insecure)
        
        return proxy
    except Exception as e:
        print(f"⚠️ خطا در VLESS: {e}")
        return None

def parse_trojan(url):
    """پارس کردن لینک TROJAN"""
    try:
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
        port = safe_int(port, 443)
        
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
        
        # TLS - بولین
        tls = param_dict.get("tls", "")
        proxy["tls"] = safe_bool(tls)
        
        # SNI
        sni = param_dict.get("sni", "")
        if sni:
            proxy["sni"] = sni
        
        # Skip Cert Verify
        allow_insecure = param_dict.get("allowInsecure", "")
        if allow_insecure:
            proxy["skip-cert-verify"] = safe_bool(allow_insecure)
        else:
            proxy["skip-cert-verify"] = True  # پیش‌فرض True برای تروجان
        
        return proxy
    except Exception as e:
        print(f"⚠️ خطا در TROJAN: {e}")
        return None

def parse_ss(url):
    """پارس کردن لینک Shadowsocks"""
    try:
        url = url.replace('ss://', '')
        
        if '@' in url:
            method_pass, rest = url.split('@', 1)
            method, password = method_pass.split(':', 1)
            server, port = rest.split(':', 1)
            port = safe_int(port, 443)
        else:
            missing_padding = len(url) % 4
            if missing_padding:
                url += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(url).decode('utf-8')
            method_pass, server_port = decoded.split('@', 1)
            method, password = method_pass.split(':', 1)
            server, port = server_port.split(':', 1)
            port = safe_int(port, 443)
        
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
        print(f"⚠️ خطا در SS: {e}")
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
        return None

def create_clash_config(proxies, config_name):
    """ایجاد کانفیگ استاندارد Clash"""
    
    # فیلتر کردن پروکسی‌های نامعتبر
    valid_proxies = []
    for p in proxies:
        if p and isinstance(p, dict) and p.get("server") and p.get("port"):
            # حذف موارد تکراری
            if p not in valid_proxies:
                valid_proxies.append(p)
    
    # محدود کردن تعداد
    max_proxies = 100
    if len(valid_proxies) > max_proxies:
        valid_proxies = valid_proxies[:max_proxies]
    
    if not valid_proxies:
        return None
    
    # ساختار پایه
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": valid_proxies,
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": [p["name"] for p in valid_proxies]
            }
        ],
        "rules": [
            "MATCH,PROXY"
        ]
    }
    
    # اضافه کردن گروه‌های بیشتر اگر پروکسی کافی باشد
    if len(valid_proxies) >= 10:
        config["proxy-groups"].append({
            "name": "Auto",
            "type": "url-test",
            "proxies": [p["name"] for p in valid_proxies],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300
        })
    
    return config

def main():
    """تابع اصلی"""
    print("🚀 شروع فرآیند تبدیل کانفیگ‌ها به فرمت Clash...")
    print(f"📅 زمان: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    os.makedirs("output", exist_ok=True)
    
    total_proxies = 0
    total_files = 0
    
    for name, url in CONFIG_URLS.items():
        print(f"\n📥 دریافت {name}...")
        
        try:
            response = requests.get(url, timeout=30)
            if response.status_code != 200:
                print(f"❌ خطا: {response.status_code}")
                continue
            
            lines = response.text.split('\n')
            proxies = []
            
            for line in lines:
                proxy = parse_config_line(line)
                if proxy:
                    proxies.append(proxy)
            
            print(f"✅ {len(proxies)} پروکسی معتبر دریافت شد")
            
            if proxies:
                # نسخه کامل
                config = create_clash_config(proxies, name)
                if config:
                    output_file = f"output/{name}.yaml"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
                    print(f"✅ {output_file} ایجاد شد")
                    total_files += 1
                    total_proxies += len(proxies)
                
                # نسخه لایت (50 تا)
                if len(proxies) > 50:
                    lite_config = create_clash_config(proxies[:50], f"{name}-lite")
                    if lite_config:
                        output_file = f"output/{name}-lite.yaml"
                        with open(output_file, 'w', encoding='utf-8') as f:
                            yaml.dump(lite_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
                        print(f"✅ {output_file} ایجاد شد (لایت)")
                        total_files += 1
                
                # نسخه مینی (20 تا)
                if len(proxies) > 20:
                    mini_config = create_clash_config(proxies[:20], f"{name}-mini")
                    if mini_config:
                        output_file = f"output/{name}-mini.yaml"
                        with open(output_file, 'w', encoding='utf-8') as f:
                            yaml.dump(mini_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
                        print(f"✅ {output_file} ایجاد شد (مینی)")
                        total_files += 1
            else:
                print(f"❌ هیچ پروکسی معتبری برای {name} یافت نشد")
                
        except Exception as e:
            print(f"❌ خطا: {str(e)}")
    
    print(f"\n🎉 فرآیند با موفقیت به پایان رسید!")
    print(f"📊 جمعاً {total_proxies} پروکسی در {total_files} فایل ذخیره شد")
    print("📁 فایل‌های خروجی در پوشه output/ قرار دارند")

if __name__ == "__main__":
    main()
