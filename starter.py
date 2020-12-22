import subprocess
import hexdump
import frida

def filterApps(apps):
    identifierKeys = ['android','com.android','com.google','com.facebook','com.amaze']
    result = list(apps)
    for app in apps:
        for key in identifierKeys:
            if app.identifier.startswith(key):
                result.remove(app)
                break
    return result

#     except frida.InvalidArgumentError as e1:
#         if str(e1) == "device not found":
#             # TODO 处理找不到 usb 设备
#             pass
#     except frida.ServerNotRunningError as e2:
#         if str(e2) == 'unable to connect to remote frida-server: closed':
#             # TODO 处理找不到 frida_server 进程
#             pass
def enumerate_apps():
    # TODO 处理多 usb 设备情况。目前多 usb 设备情况下 get_usb_device 会返回第一个 usb 设备
    device = frida.get_usb_device()
    return filterApps(device.enumerate_applications())

def enumerate_usb_devices():
    devices = frida.enumerate_devices()
    return [device for device in devices if device.type == 'usb']

def find_frida_version():
    return subprocess.check_output(["frida",'--v']).decode('utf-8').strip('\n')

def frida_server_exist():
    result = subprocess.check_output(['adb', 'shell', 'ls /data/local/tmp']).decode('utf-8').strip('\n')
    return result.find('frida-server') != -1

def kill_frida_server():
    pid = subprocess.check_output(['adb','shell',"ps | grep data/local/tmp/frida-server | awk '{print $2}'"]).decode('utf-8').strip("\n")
    if pid.isnumeric:
        subprocess.call(['adb','shell','kill %s' % pid])

def start_frida_server():
    kill_frida_server()
    subprocess.call(['adb','shell','/data/local/tmp/frida-server &'])

def setup_frida_server(filename):
    subprocess.call(['adb','push',filename,'/data/local/tmp/frida-server'])
    subprocess.call(['adb','shell','chmod 755 /data/local/tmp/frida-server'])


import requests
import time

def download_frida_server(name, url, callback):
    # headers = {'Proxy-Connection':'keep-alive'}
    r = requests.get(url, stream=True)
    length = float(r.headers['content-length'])
    f = open(name, 'wb')
    count = 0
    count_tmp = 0
    time1 = time.time()
    for chunk in r.iter_content(chunk_size = 512):
        if chunk:
            f.write(chunk)
            count += len(chunk)
            if time.time() - time1 > 2:
                p = count / length * 100
                speed = (count - count_tmp) / 1024 / 1024 / 2
                count_tmp = count
                callback(formatFloat(p), formatFloat(speed))
                #print(name + ': ' + formatFloat(p) + '%' + ' Speed: ' + formatFloat(speed) + 'M/S')
                time1 = time.time()
    f.close()
    
def formatFloat(num):
    return '{:.2f}'.format(num)

# v = find_frida_version()
# address = "https://github.com/frida/frida/releases/download/" + v + "/frida-server-" + v + "-android-x86.xz"
# print(address)
# downloadFile("frida-server",address)