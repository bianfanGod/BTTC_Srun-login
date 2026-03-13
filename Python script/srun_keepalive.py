import os
import sys
import time
import json
import subprocess
import configparser
import requests
from typing import Optional
from plyer import notification

# 导入本地的加密依赖库 (依赖同目录的 encryptlib.py 和 xxtea)
try:
    from encryptlib import hmd5, sha1, chkstr, info_
except ImportError:
    # 如果找不到依赖，弹窗报错并退出
    notification.notify(title="致命错误", message="找不到 encryptlib.py 模块，请确保它在同级目录下！", app_name="校园网保活助手", timeout=5)
    sys.exit(1)

# === 常量配置 ===
CONFIG_FILE = "config.ini"
URL = {
    'rad_user_info': 'http://10.136.0.8/cgi-bin/rad_user_info',
    'get_challenge': 'http://10.136.0.8/cgi-bin/get_challenge',
    'srun_portal'  : 'http://10.136.0.8/cgi-bin/srun_portal'
}
CALLBACK = "jQueryCallback"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TYPE = "1"
N = "200"
ENC = 'srun_bx1'
ACID = "6"

# 全局请求会话，保持 TCP 连接和伪装浏览器
session = requests.Session()
session.headers.update({"User-Agent": UA})

# === 核心交互：Windows 通知与配置读取 ===

def send_toast(title: str, message: str):
    """发送 Windows 系统通知"""
    try:
        notification.notify(
            title=title,
            message=message,
            app_name="保活助手",
            timeout=5
        )
    except Exception as e:
        pass # 静默处理通知发送失败的异常

def load_config():
    """读取或生成 config.ini 配置文件"""
    config = configparser.ConfigParser()
    
    # 兼容 PyInstaller 打包后的路径定位
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
        
    config_path = os.path.join(application_path, CONFIG_FILE)

    if not os.path.exists(config_path):
        # 首次启动生成模板
        config['ACCOUNT'] = {
            'Username': '',
            'Password': ''
        }
        config['SETTINGS'] = {
            'PingInterval_Minutes': '5',
            'TestHosts': '223.5.5.5, 8.8.8.8, www.baidu.com'
        }
        with open(config_path, 'w', encoding='utf-8') as f:
            config.write(f)
        
        send_toast("初始化完成", "已在目录下生成 config.ini，请填写账号密码后重新启动程序。")
        sys.exit(0)
        
    # 读取配置
    config.read(config_path, encoding='utf-8')
    username = config.get('ACCOUNT', 'Username', fallback='')
    password = config.get('ACCOUNT', 'Password', fallback='')
    hosts_str = config.get('SETTINGS', 'TestHosts', fallback='223.5.5.5')
    interval = config.getint('SETTINGS', 'PingInterval_Minutes', fallback=5)
    
    if not username or not password:
        send_toast("配置错误", "config.ini 中的账号或密码为空，请填写后重启！")
        sys.exit(1)
        
    test_hosts = [h.strip() for h in hosts_str.split(',')]
    return username, password, test_hosts, interval

# === 深澜认证逻辑 ===

def parse_jsonp(text: str) -> dict:
    """解析深澜特有的 JSONP 格式"""
    start = text.find('(')
    end = text.rfind(')')
    if start != -1 and end != -1:
        return json.loads(text[start+1 : end])
    raise ValueError(f"无法匹配 JSONP 数据格式: {text}")

def get_ip() -> Optional[str]:
    try:
        resp = session.get(URL['rad_user_info'], params={"callback": CALLBACK}, timeout=5)
        data = parse_jsonp(resp.text)
        if 'error_msg' in data and data['error_msg']: return None
        return data.get('client_ip') or data.get('online_ip')
    except:
        return None

def get_challenge(username: str, ip: str) -> Optional[str]:
    try:
        resp = session.get(URL['get_challenge'], params={"callback": CALLBACK, "username": username, "ip": ip}, timeout=5)
        data = parse_jsonp(resp.text)
        if 'error_msg' in data and data['error_msg']: return None
        return data.get('challenge')
    except:
        return None

def srun_portal_login(username, password, token, ip) -> bool:
    try:
        # 调用本地 encryptlib 计算加密参数
        hmd5_password = hmd5(password, token)
        info = info_({"username": username, "password": password, "ip": ip, "acid": ACID, "enc_ver": ENC}, token)
        chksum = sha1(chkstr(token, username, hmd5_password, ACID, ip, N, TYPE, info))
    except Exception:
        return False

    params = {
        "action": 'login', "callback": CALLBACK, "username": username,
        "password": '{MD5}' + hmd5_password, "os": "Windows", "name": "Windows",
        "nas_ip": '', "double_stack": 0, "chksum": chksum, "info": info,
        "ac_id": ACID, "ip": ip, "n": N, "type": TYPE, "captchaVal": '',
        '_': int(time.time() * 1000)
    }

    try:
        resp = session.get(URL['srun_portal'], params=params, timeout=5)
        data = parse_jsonp(resp.text)
        return data.get('res') == 'ok'
    except:
        return False

def execute_login(username, password) -> bool:
    """组合深澜登录三步曲"""
    ip = get_ip()
    if not ip: return False
    token = get_challenge(username, ip)
    if not token: return False
    return srun_portal_login(username, password, token, ip)

# === 保活探测主干逻辑 ===

def check_internet(test_hosts) -> bool:
    """执行 Windows Ping，彻底隐藏控制台黑框"""
    for host in test_hosts:
        command = ['ping', '-n', '1', '-w', '2000', host]
        try:
            # subprocess.CREATE_NO_WINDOW (0x08000000) 确保不会闪黑框
            response = subprocess.run(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                creationflags=0x08000000 
            )
            if response.returncode == 0:
                return True
        except:
            continue
    return False

def main():
    username, password, test_hosts, interval = load_config()
    send_toast("服务已启动", f"正在后台默默守护你的网络，检测间隔: {interval}分钟。")
    
    while True:
        if check_internet(test_hosts):
            # 网络正常，休眠设定的时间
            time.sleep(interval * 60)
        else:
            # 断网处理
            send_toast("网络断开", "检测到无互联网连接，正在自动重连校园网...")
            success = execute_login(username, password)
            
            if success:
                send_toast("重连成功", "深澜校园网已重新认证，网络恢复通畅。")
                time.sleep(60) # 成功后冷却 1 分钟
            else:
                send_toast("重连失败", "认证未能成功，请检查网关状态或账号密码。")
                time.sleep(30) # 失败后冷却 30 秒再试

if __name__ == '__main__':
    main()
