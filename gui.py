from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from mysniffer import *

import sys

bg_color = {
    "ARP":"#30c9e8",
    "IP":"#f66071",
    "ICMP":"#fbc900",
    "TCP":"#30c9e8",
    "UDP":"#8dc3e0",
    "HTTP":"#0251ff",
    "HTTPS":"#faf5e6",
    "DNS":"#ffccff"
}

class AppUi(QMainWindow):
    def __init__(self, parent=None):
        QMainWindow.__init__(self)
        self.setWindowTitle("MySniffer")
        self.resize(1000,800)
        self.Widget = QWidget(self)

        # 网格布局
        self.gridLayout = QGridLayout(self.Widget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setSpacing(6)

        self.headLayout = QHBoxLayout()
        self.headLayout.setContentsMargins(10, 5, 10, 2)
        self.headLayout.setSpacing(20)

        self.contentLayout = QVBoxLayout()
        self.contentLayout.setContentsMargins(10, 0, 10, 10)
        self.contentLayout.setSpacing(6)

        font = QFont()
        font.setFamily("Courier")
        font.setBold(0.5)
        font.setPointSize(15)


        # 第一层：展示正在抓取的数据包
        self.overviewTree = QTreeWidget(self.Widget)
        self.overviewTree.setFrameStyle(QFrame.Panel | QFrame.Raised)
        self.overviewTree.setRootIsDecorated(False)
        self.overviewTree.setAutoScroll(True)
        self.overviewTree.setFont(font)
        self.overviewTree.setUniformRowHeights(True)

        self.overviewTree.setColumnCount(7)
        self.overviewTree.headerItem().setText(0, "No.")
        self.overviewTree.headerItem().setText(1, "Time")
        self.overviewTree.headerItem().setText(2, "Source")
        self.overviewTree.headerItem().setText(3, "Destination")
        self.overviewTree.headerItem().setText(4, "Protocol")
        self.overviewTree.headerItem().setText(5, "Length")
        self.overviewTree.headerItem().setText(6, "Info")
        self.overviewTree.setSortingEnabled(True)
        self.overviewTree.sortItems(0, Qt.AscendingOrder)
        self.overviewTree.setColumnWidth(0, 75)
        self.overviewTree.setColumnWidth(1, 130)
        self.overviewTree.setColumnWidth(2, 150)
        self.overviewTree.setColumnWidth(3, 150)
        self.overviewTree.setColumnWidth(4, 85)
        self.overviewTree.setColumnWidth(5, 60)
        self.overviewTree.setSelectionBehavior(
            QTreeWidget.SelectRows)
        self.overviewTree.setSelectionMode(QTreeWidget.SingleSelection)
        self.overviewTree.clicked.connect(self.on_tableview_clicked)

        for i in range(7):
            self.overviewTree.headerItem().setBackground(i,QBrush(QColor(Qt.white)))
        
        # 第二层，显示详细包数据
        self.pktWidget = QTreeWidget(self.Widget)
        self.pktWidget.header().setStretchLastSection(True)
        self.pktWidget.header().hide()

        font.setFamily("Courier New")
        font.setBold(0.8)
        font.setPointSize(18)
        self.pktWidget.setFont(font)
        self.pktWidget.setAutoScroll(True)
        self.pktWidget.setTextElideMode(Qt.ElideMiddle)
        self.pktWidget.setColumnCount(1)
        self.pktWidget.setFrameStyle(QFrame.Panel | QFrame.Raised)

        # 第三层，显示十六进制和字符串
        self.hexBrowser = QTextBrowser(self.Widget)
        self.hexBrowser.setText("")
        self.hexBrowser.setFont(font)
        self.hexBrowser.setFrameStyle(QFrame.Panel | QFrame.Raised)

        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.overviewTree)
        self.splitter.addWidget(self.pktWidget)
        self.splitter.addWidget(self.hexBrowser)
        self.contentLayout.addWidget(self.splitter)
        self.gridLayout.addLayout(self.contentLayout, 1, 0, 1, 1)
        
        QMetaObject.connectSlotsByName(self)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.overviewTree.scrollToBottom)
        self.timer.start(100)

        self.sniffer = MySniffer(self)
        self.setCentralWidget(self.Widget)

        self.sniffer.push_start()



    def on_tableview_clicked(self):
        pkt_id = self.overviewTree.currentItem().text(0)
        if pkt_id and pkt_id.isdigit():
            self.timer.stop()

            result = self.sniffer.parse_pkt_detail(int(pkt_id))
            self.pktWidget.clear()
            for item in result:
                tmp_result = QTreeWidgetItem(self.pktWidget)
                tmp_result.setBackground(0 ,QBrush(QColor("#f5f2f2")))
                tmp_result.setText(0, item[0])
                for detail_info in item[1]:
                    ttmp = QTreeWidgetItem(tmp_result)
                    ttmp.setText(0, detail_info)


    def add_pkt_to_tree(self, pkt_id, pkt_time, src, dst, protocol, \
                        pkt_len, pkt_info):
        if protocol in bg_color:
            color = bg_color[protocol]
        else:
            color = Qt.white
        item = QTreeWidgetItem(self.overviewTree)
        for i in range(7):
            item.setBackground(i, QBrush(QColor(color)))
        item.setData(0, Qt.DisplayRole, pkt_id)
        item.setText(1, "%s" % pkt_time)
        item.setText(2, src)
        item.setText(3, dst)
        item.setText(4, protocol)
        item.setData(5, Qt.DisplayRole, pkt_len)
        item.setText(6, pkt_info)


def start():
    app = QApplication([])
    window = AppUi()
    window.show()
    app.exec()

start()