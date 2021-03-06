from PyQt5.QtCore import (QRegExp, QSortFilterProxyModel, Qt, QThread, pyqtSignal)
from PyQt5.QtGui import QStandardItemModel
from PyQt5.QtWidgets import (QApplication, QCheckBox, QComboBox, QGridLayout,
        QGroupBox, QLabel, QLineEdit, QTreeView, QVBoxLayout,
        QWidget, QAbstractItemView, QTextEdit, QSplitter, QInputDialog, QAction, QMenuBar, QMessageBox, QProgressDialog)
from packet import Packet, nextPacket
from starter import *
import time
import hexdump
import subprocess
import signal
import os       

import sys
print(sys.version)

# SUBJECT, SENDER, DATE = range(3)
NUMBER, TIME, SOURCE, DESTINATION, PROTOCOL, LENGTH, INFO = range(7)

class Window(QWidget):
    def __init__(self):
        super(Window, self).__init__()
        
        self.menu = QMenuBar(self)
        newAct = QAction('打开', self)   
        newAct.triggered.connect(self.chooseApps)     
        self.menu.addMenu('文件').addAction(newAct)
        

        self.global_packets = []
        self.proxyModel = QSortFilterProxyModel()
        self.proxyModel.setDynamicSortFilter(True)

        self.proxyGroupBox = QGroupBox("Sorted/Filtered Model")

        self.proxyView = QTreeView()
        self.proxyView.setRootIsDecorated(False)
        self.proxyView.setAlternatingRowColors(True)
        self.proxyView.setModel(self.proxyModel)
        # 设置行内容不可更改
        self.proxyView.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        self.filterCaseSensitivityCheckBox = QCheckBox("Case sensitive filter")

        self.filterPatternLineEdit = QLineEdit()
        self.filterPatternLabel = QLabel("Filter &pattern:")
        self.filterPatternLabel.setBuddy(self.filterPatternLineEdit)

        self.filterSyntaxComboBox = QComboBox()
        self.filterSyntaxComboBox.addItem("Regular expression", QRegExp.RegExp)
        self.filterSyntaxComboBox.addItem("Wildcard", QRegExp.Wildcard)
        self.filterSyntaxComboBox.addItem("Fixed string", QRegExp.FixedString)
        self.filterSyntaxLabel = QLabel("Filter &syntax:")
        self.filterSyntaxLabel.setBuddy(self.filterSyntaxComboBox)

        self.filterColumnComboBox = QComboBox()
        self.filterColumnComboBox.addItem("NO.")
        self.filterColumnComboBox.addItem("Time")
        self.filterColumnComboBox.addItem("Source")        
        self.filterColumnComboBox.addItem("Destination")
        self.filterColumnComboBox.addItem("Protocol")
        self.filterColumnComboBox.addItem("Length")
        self.filterColumnComboBox.addItem("Info")

        self.filterColumnLabel = QLabel("Filter &column:")
        self.filterColumnLabel.setBuddy(self.filterColumnComboBox)

        self.filterPatternLineEdit.textChanged.connect(self.filterRegExpChanged)
        self.filterSyntaxComboBox.currentIndexChanged.connect(self.filterRegExpChanged)
        self.filterColumnComboBox.currentIndexChanged.connect(self.filterColumnChanged)
        self.filterCaseSensitivityCheckBox.toggled.connect(self.filterRegExpChanged)

        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.proxyView)
        self.detailLabel = QTextEdit()
        self.detailLabel.setReadOnly(True)
        self.splitter.addWidget(self.detailLabel)
        self.rawLabel = QTextEdit()
        self.rawLabel.setReadOnly(True)
        self.splitter.addWidget(self.rawLabel)
        # 默认缩起 rawLabel
        self.splitter.setSizes([200,400,0])
        self.proxyView.clicked.connect(self.onModelClicked)

        proxyLayout = QGridLayout()
        proxyLayout.addWidget(self.filterPatternLabel, 0, 0)
        proxyLayout.addWidget(self.filterPatternLineEdit, 0, 1)
        proxyLayout.addWidget(self.filterSyntaxLabel, 0, 2)
        proxyLayout.addWidget(self.filterSyntaxComboBox, 0, 3)
        proxyLayout.addWidget(self.filterColumnLabel, 0, 4)
        proxyLayout.addWidget(self.filterColumnComboBox, 0,5 )
        proxyLayout.addWidget(self.filterCaseSensitivityCheckBox, 0,6)
        # proxyLayout.addWidget(self.proxyView, 4, 0, 1, 7)
        proxyLayout.addWidget(self.splitter, 1, 0, 1 ,7)

        self.proxyGroupBox.setLayout(proxyLayout)

        mainLayout = QVBoxLayout()

        mainLayout.addWidget(self.proxyGroupBox)
        self.setLayout(mainLayout)

        self.setWindowTitle("Basic Sort/Filter Model")
        self.resize(1000, 600)

        self.filterColumnComboBox.setCurrentIndex(INFO)

        self.filterCaseSensitivityCheckBox.setChecked(True)
        self.proxyModel.setSourceModel(self.createModel())

    def filterRegExpChanged(self):
        syntax_nr = self.filterSyntaxComboBox.itemData(self.filterSyntaxComboBox.currentIndex())
        syntax = QRegExp.PatternSyntax(syntax_nr)

        if self.filterCaseSensitivityCheckBox.isChecked():
            caseSensitivity = Qt.CaseSensitive
        else:
            caseSensitivity = Qt.CaseInsensitive

        regExp = QRegExp(self.filterPatternLineEdit.text(),
                caseSensitivity, syntax)
        self.proxyModel.setFilterRegExp(regExp)

    def filterColumnChanged(self):
        self.proxyModel.setFilterKeyColumn(self.filterColumnComboBox.currentIndex())
    
    def createModel(self):
        model = QStandardItemModel(0, 7, self)

        model.setHeaderData(NUMBER, Qt.Horizontal, "No.")
        model.setHeaderData(TIME, Qt.Horizontal, "Time")
        model.setHeaderData(SOURCE, Qt.Horizontal, "Source")
        model.setHeaderData(DESTINATION, Qt.Horizontal, "Destination")
        model.setHeaderData(PROTOCOL, Qt.Horizontal, "Protocol")
        model.setHeaderData(LENGTH, Qt.Horizontal, "Length")
        model.setHeaderData(INFO, Qt.Horizontal, "Info")
        return model

    def addModel(self, packet):
        last_index = self.proxyModel.rowCount()
        self.proxyModel.insertRow(last_index)
        self.proxyModel.setData(self.proxyModel.index(last_index, NUMBER), packet.frame)
        self.proxyModel.setData(self.proxyModel.index(last_index, TIME), packet.packet_header.timestamp_second)
        self.proxyModel.setData(self.proxyModel.index(last_index, SOURCE), packet.ipv4_header.src_addr)
        self.proxyModel.setData(self.proxyModel.index(last_index, DESTINATION), packet.ipv4_header.dest_addr)
        self.proxyModel.setData(self.proxyModel.index(last_index, PROTOCOL), "HTTP")
        self.proxyModel.setData(self.proxyModel.index(last_index, LENGTH), packet.ipv4_header.total_length)
        self.proxyModel.setData(self.proxyModel.index(last_index, INFO), str(packet.tcp_data.info))
        self.global_packets.append(packet)

    def onModelClicked(self, modelIndex):
        packet = self.global_packets[modelIndex.row()]
        if packet.tcp_data.extra != None:
            self.detailLabel.setText("%s\n\n以下是贴心小顾帮您自动解码的 data_list 内容:\n\n%s" % (str(packet.tcp_data), packet.tcp_data.extra))
        else:
            self.detailLabel.setText(str(packet.tcp_data))
        self.rawLabel.setText(hexdump.hexdump(packet.tcp_data.raw,'return'))

    def moniter(self, filename):
        self.monitor_thread = MonitorThread(filename)
        self.monitor_thread.start()
        self.monitor_thread.trigger.connect(self.addModel)

    def chooseApps(self):
        print("chooseApps")
        try:
            apps = enumerate_apps()
            if apps != None and len(apps) > 0:
                name,ok = QInputDialog().getItem(window, "选择 App", "可选列表", (app.name for app in apps), 0 , False)
                if ok:
                    app = [child for child in apps if child.name == name][0]
                    print(subprocess.check_output("pwd", shell=True))

                    log = 'r0capture/%s.pcap' % app.name
                    if not os.path.exists(log):
                        subprocess.call(['touch', log])
                    
                    if app.pid != 0:
                        # TODO attach 模式
                        self.worker = subprocess.Popen("cd r0capture && %s r0capture.py -U %s -p %s.pcap" % (sys.executable, app.identifier, app.name), shell=True)
                    else:
                        # TODO spawn 模式
                        self.worker = subprocess.Popen("cd r0capture && %s r0capture.py -U -f %s -p %s.pcap" % (sys.executable, app.identifier, app.name), shell=True)
                    r = subprocess.check_output("ps -A | grep r0capture.py",shell=True)
                    QMessageBox.information(self, '提示', str(r))
                    self.moniter("r0capture/%s.pcap" % app.name)
        except frida.InvalidArgumentError as e1:
            if str(e1) == "device not found":
                # 处理找不到 usb 设备
                QMessageBox.information(self, '提示', '找不到 usb 设备')
        except (frida.ServerNotRunningError, frida.TransportError) as e2:
            if (str(e2) == 'unable to connect to remote frida-server: closed') or (str(e2) == 'the connection is closed'):
                # TODO 处理找不到 frida_server 进程
                if frida_server_exist():
                    kill_frida_server()
                    start_frida_server()
                    if frida_server_exist():
                        self.chooseApps()
                    else:
                        QMessageBox.information(self, '提示', 'frida-server 启动异常')
                else:
                    result = QMessageBox.question(self, '询问', "需要我帮你配置 frida-server 么?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                    if result == QMessageBox.Yes:
                        def finish():
                            setup_frida_server()
                            start_frida_server()
                            self.chooseApps()
                        self.download(finish)
                    else:
                        QMessageBox.information(self, '提示', '找不到 frida-server 程序')
    
    def download(self,finish):
        progress = QProgressDialog(self)
        progress.setWindowTitle("请稍等")  
        progress.setLabelText("当前车速 0M/S")
        progress.setWindowModality(Qt.WindowModal)
        progress.setRange(0, 100)

        def cancel():
            if hasattr(self, 'download_thread'):
                self.download_thread.terminate()

        progress.canceled.connect(cancel)

        def update(args):
            if args[0] == "over":
                progress.setValue(100)
                progress.setLabelText("下载完成")
                finish()
            else:
                progress.setValue(float(args[0]))
                progress.setLabelText("当前车速 %sM/S" % args[1])

        self.download_thread = DownloadThread()
        self.download_thread.start()
        self.download_thread.trigger.connect(update)        

    def closeEvent(self, event):
        if hasattr(self, 'worker'):
            # os.killpg(os.getpgid(self.worker.pid), signal.SIGTERM)
            # terminate 其实并不能真正杀死，需要用 os.killpg，但 os.killpg 会导致 app 崩溃。
            self.worker.terminate()
        if hasattr(self, 'download_thread'):
            self.download_thread.terminate()
        if hasattr(self,'monitor_thread'):
            self.monitor_thread.terminate()

class DownloadThread(QThread):
    trigger = pyqtSignal(list)

    def __init__(self):
        super(DownloadThread, self).__init__()

    def run(self):
        def emit(progress, speed):
            self.trigger.emit([progress,speed])
        download_frida_server(find_frida_version(), emit)

class MonitorThread(QThread):
    trigger = pyqtSignal(Packet)
    def __init__(self, filename):
        self.filename = filename
        super(MonitorThread, self).__init__()
    
    def run(self):
        time.sleep(3)
        with open(self.filename,"rb") as f:
            while True:
                packet = nextPacket(f)
                if packet != None:
                    #self.addModel(packet)
                    self.trigger.emit(packet)
                else:
                    time.sleep(3)

if __name__ == '__main__':

    import sys

    qApplication = QApplication(sys.argv)
    window = Window()
    window.show()
    window.chooseApps()

    sys.exit(qApplication.exec_())