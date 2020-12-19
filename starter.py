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

def enumerate_apps():
    try:
        # TODO 处理多 usb 设备情况。目前多 usb 设备情况下 get_usb_device 会返回第一个 usb 设备
        device = frida.get_usb_device()
        return filterApps(device.enumerate_applications())
    except frida.InvalidArgumentError as e1:
        if str(e1) == "device not found":
            # TODO 处理找不到 usb 设备
            pass
    except frida.ServerNotRunningError as e2:
        if str(e2) == 'unable to connect to remote frida-server: closed':
            # TODO 处理找不到 frida_server 进程
            pass
    return None