import requests
import yaml
import json
import os
import base64
import urllib.parse
from datetime import datetime
import re
import logging

# تنظیم لاگینگ
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# لینک‌های کانفیگ
CONFIG_URLS = {
    "mixed": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/mixed-all.txt",
    "lite": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/mixed-light-all.txt",
    "vmess": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/vmess-all.txt",
    "vless": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/vless-all.txt",
    "trojan": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/trojan-all.txt",
    "ss": "https://raw.githubusercontent.com/amirkma/My-Config-Collector/refs/heads/main/configs/ss-all.txt"
}

# متدهای معتبر Shadowsocks
VALID_SS_CIPHERS = [
    'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'chacha20-ietf-poly1305', 'chacha20-ietf', 'chacha20',
    'xchacha20-ietf-poly1305', 'xchacha20',
    'rc4-md5', 'salsa20'
]

def safe_bool(value):
    """تبدیل ایمن به بولین"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ['true', '1', 't', 'yes', 'y', 'tls', 'enable']
    if isinstance(value, (int, float)):
        return bool(value)
    return False

def safe_int(value, default=0):
    """تبدیل ایمن به عدد"""
    try:
        if isinstance(value, str):
            value = re.sub(r'[^0-9]', '', value)
            if not value:
                return default
        return int(float(value))
    except (ValueError, TypeError):
        return default

def clean_short_id(sid):
    """پاکسازی و اعتبارسنجی short-id برای Reality"""
    if not sid:
        return None
    cleaned = re.sub(r'[^a-f0-9]', '', str(sid).lower())
    if len(cleaned) < 2 or len(cleaned) > 8:
        return None
    return cleaned

def decode_base64_url(data):
    """دیکد کردن Base64 با پشتیبانی از URL-safe"""
    try:
        data = data.strip()
        # حذف whitespace و کاراکترهای اضافی
        data = re.sub(r'\s+', '', data)
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        data = data.replace('-', '+').replace('_', '/')
        return base64.b64decode(data).decode('utf-8')
    except Exception:
        return None

def is_valid_ss_cipher(cipher):
    """بررسی معتبر بودن متد SS"""
    if not cipher:
        return False
    cipher = cipher.lower().strip()
    return cipher in VALID_SS_CIPHERS

def parse_vmess(url):
    """پارس کردن لینک VMESS"""
    try:
        encoded = url.replace('vmess://', '').strip()
        decoded = decode_base64_url(encoded)
        if not decoded:
            return None
        
        data = json.loads(decoded)
        
        # اعتبارسنجی اولیه
        if not data.get("add") or not data.get("id"):
            return None
        
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
        
        # TLS
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
    except Exception:
        return None

def parse_vless(url):
    """پارس کردن لینک VLESS"""
    try:
        url = url.replace('vless://', '').strip()
        
        if '@' not in url:
            return None
        
        uuid, rest = url.split('@', 1)
        
        if '?' not in rest:
            server_port = rest
            params = ''
        else:
            server_port, params = rest.split('?', 1)
        
        if ':' not in server_port:
            return None
            
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
        
        if not proxy["server"] or not proxy["uuid"]:
            return None
        
        # TLS
        security = param_dict.get("security", "")
        proxy["tls"] = safe_bool(security) or security == "reality"
        
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
            
            reality_opts = {}
            
            pbk = param_dict.get("pbk", "")
            if pbk:
                reality_opts["public-key"] = pbk
            
            sid = param_dict.get("sid", "")
            if sid:
                cleaned_sid = clean_short_id(sid)
                if cleaned_sid:
                    reality_opts["short-id"] = cleaned_sid
            
            fp = param_dict.get("fp", "")
            if fp:
                reality_opts["fingerprint"] = fp
            
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
        
        return proxy
    except Exception:
        return None

def parse_trojan(url):
    """پارس کردن لینک TROJAN"""
    try:
        url = url.replace('trojan://', '').strip()
        
        if '@' not in url:
            return None
        
        password, rest = url.split('@', 1)
        
        if '?' not in rest:
            server_port = rest
            params = ''
        else:
            server_port, params = rest.split('?', 1)
        
        if ':' not in server_port:
            return None
            
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
        
        if not proxy["server"] or not proxy["password"]:
            return None
        
        # TLS
        tls = param_dict.get("tls", "")
        proxy["tls"] = safe_bool(tls) or True
        
        # SNI
        sni = param_dict.get("sni", "")
        if sni:
            proxy["sni"] = sni
        
        # Skip Cert Verify
        allow_insecure = param_dict.get("allowInsecure", "")
        if allow_insecure:
            proxy["skip-cert-verify"] = safe_bool(allow_insecure)
        else:
            proxy["skip-cert-verify"] = True
        
        return proxy
    except Exception:
        return None

def parse_ss(url):
    """پارس کردن لینک Shadowsocks با اعتبارسنجی قوی"""
    try:
        url = url.replace('ss://', '').strip()
        
        # حذف کاراکترهای غیرمجاز
        url = re.sub(r'[^\w\d:@/?&=+%.-]', '', url)
        
        if not url:
            return None
        
        method = None
        password = None
        server = None
        port = None
        
        # فرمت 1: ss://method:password@server:port
        if '@' in url:
            method_pass, rest = url.split('@', 1)
            
            # بررسی روش
            if ':' in method_pass:
                method, password = method_pass.split(':', 1)
                # اعتبارسنجی متد
                if not is_valid_ss_cipher(method):
                    return None
            else:
                # ممکنه base64 باشه
                decoded = decode_base64_url(method_pass)
                if decoded and ':' in decoded:
                    method, password = decoded.split(':', 1)
                    if not is_valid_ss_cipher(method):
                        return None
                else:
                    return None
            
            # جدا کردن server:port
            if ':' not in rest:
                return None
            # استفاده از rsplit برای پشتیبانی از IPv6
            server, port = rest.rsplit(':', 1)
            port = safe_int(port, 443)
        
        # فرمت 2: ss://base64_encoded
        else:
            decoded = decode_base64_url(url)
            if not decoded:
                return None
            
            # فرمت decoded: method:password@server:port
            if '@' not in decoded:
                return None
                
            method_pass, rest = decoded.split('@', 1)
            if ':' not in method_pass or ':' not in rest:
                return None
                
            method, password = method_pass.split(':', 1)
            if not is_valid_ss_cipher(method):
                return None
                
            server, port = rest.rsplit(':', 1)
            port = safe_int(port, 443)
        
        # اعتبارسنجی نهایی
        if not all([method, password, server, port]):
            return None
        
        if port <= 0 or port > 65535:
            return None
        
        # اسم پروکسی
        proxy_name = f"SS-{server}-{method[:8]}"
        
        proxy = {
            "name": proxy_name,
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method.lower(),
            "password": password,
            "udp": True
        }
        
        return proxy
    except Exception:
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
    except Exception:
        return None

def create_clash_config(proxies, config_name):
    """ایجاد کانفیگ استاندارد Clash"""
    
    # فیلتر کردن پروکسی‌های نامعتبر و تکراری
    valid_proxies = []
    seen_names = set()
    
    for p in proxies:
        if not p or not isinstance(p, dict):
            continue
        
        # بررسی وجود فیلدهای ضروری
        if not p.get("server") or not p.get("port") or not p.get("type"):
            continue
        
        # بررسی نوع
        if p["type"] == "ss":
            if not p.get("cipher") or not p.get("password"):
                continue
            # بررسی متد معتبر
            if not is_valid_ss_cipher(p["cipher"]):
                continue
        
        # حذف موارد تکراری بر اساس نام
        name = p.get("name", "")
        if name in seen_names:
            continue
        seen_names.add(name)
        
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
    if len(valid_proxies) >= 5:
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
    logger.info("🚀 شروع فرآیند تبدیل کانفیگ‌ها به فرمت Clash...")
    logger.info(f"📅 زمان: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    os.makedirs("output", exist_ok=True)
    
    total_proxies = 0
    total_files = 0
    total_errors = 0
    
    for name, url in CONFIG_URLS.items():
        logger.info(f"\n📥 دریافت {name}...")
        
        try:
            response = requests.get(url, timeout=30)
            if response.status_code != 200:
                logger.error(f"❌ خطا: {response.status_code}")
                continue
            
            lines = response.text.split('\n')
            proxies = []
            error_count = 0
            
            for line in lines:
                proxy = parse_config_line(line)
                if proxy:
                    proxies.append(proxy)
                else:
                    if line.strip() and not line.strip().startswith('#'):
                        error_count += 1
            
            logger.info(f"✅ {len(proxies)} پروکسی معتبر دریافت شد")
            if error_count > 0:
                logger.warning(f"⚠️ {error_count} لینک نامعتبر نادیده گرفته شد")
                total_errors += error_count
            
            if proxies:
                # نسخه کامل
                config = create_clash_config(proxies, name)
                if config:
                    output_file = f"output/{name}.yaml"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
                    logger.info(f"✅ {output_file} ایجاد شد")
                    total_files += 1
                    total_proxies += len(proxies)
                
                # نسخه لایت (50 تا)
                if len(proxies) > 50:
                    lite_config = create_clash_config(proxies[:50], f"{name}-lite")
                    if lite_config:
                        output_file = f"output/{name}-lite.yaml"
                        with open(output_file, 'w', encoding='utf-8') as f:
                            yaml.dump(lite_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
                        logger.info(f"✅ {output_file} ایجاد شد (لایت)")
                        total_files += 1
                
                # نسخه مینی (20 تا)
                if len(proxies) > 20:
                    mini_config = create_clash_config(proxies[:20], f"{name}-mini")
                    if mini_config:
                        output_file = f"output/{name}-mini.yaml"
                        with open(output_file, 'w', encoding='utf-8') as f:
                            yaml.dump(mini_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
                        logger.info(f"✅ {output_file} ایجاد شد (مینی)")
                        total_files += 1
            else:
                logger.warning(f"❌ هیچ پروکسی معتبری برای {name} یافت نشد")
                
        except Exception as e:
            logger.error(f"❌ خطا در پردازش {name}: {str(e)}")
    
    logger.info(f"\n🎉 فرآیند با موفقیت به پایان رسید!")
    logger.info(f"📊 جمعاً {total_proxies} پروکسی در {total_files} فایل ذخیره شد")
    logger.info(f"⚠️ {total_errors} لینک نامعتبر نادیده گرفته شد")
    logger.info("📁 فایل‌های خروجی در پوشه output/ قرار دارند")

if __name__ == "__main__":
    main()
