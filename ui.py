from PyQt5.QtCore import (QDate, QDateTime, QRegExp, QSortFilterProxyModel, Qt,
        QTime)
from PyQt5.QtGui import QStandardItemModel
from PyQt5.QtWidgets import (QApplication, QCheckBox, QComboBox, QGridLayout,
        QGroupBox, QHBoxLayout, QLabel, QLineEdit, QTreeView, QVBoxLayout,
        QWidget, QAbstractItemView, QTextEdit, QSplitter)
from packet import nextPacket
import time
import hexdump


# SUBJECT, SENDER, DATE = range(3)
NUMBER, TIME, SOURCE, DESTINATION, PROTOCOL, LENGTH, INFO = range(7)

class Window(QWidget):
    def __init__(self):
        super(Window, self).__init__()

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
        
if __name__ == '__main__':

    import sys

    app = QApplication(sys.argv)
    window = Window()
    # window.setSourceModel(createModel(window))
    window.show()

    with open("/Users/guxin/Downloads/r0capture/test.pcap","rb") as f:
        while True:
            packet = nextPacket(f)
            #print(packet)
            if packet != None:
                window.addModel(packet)
            else:
                break

    sys.exit(app.exec_())