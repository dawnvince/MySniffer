from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5 import *

from mysniffer import *

import sys
import shutil

bg_color = {
    "ARP":"#30c9e8",
    "IP":"#f66071",
    "ICMP":"#0251ff",
    "TCP":"#30c9e8",
    "UDP":"#fbc900",
    "HTTP":"#8dc3e0",
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

        self.mainToolBar = QToolBar(self)
        self.addToolBar(Qt.TopToolBarArea, self.mainToolBar)
        # self.mainToolBar.setStyleSheet("background: #FFFAFA;")
        self.mainToolBar.setMaximumHeight(150)
        
        font = QFont()

        # 几个按钮
        self.start_action = QAction(self)
        icon_start = QIcon()
        icon_start.addPixmap(QPixmap("icon/播放.png"), QIcon.Normal, QIcon.Off)
        self.start_action.setIcon(icon_start)
        self.start_action.setText("开始")
        self.start_action.triggered.connect(self.on_start_action_clicked)

        self.pause_action = QAction(self)
        icon_pause = QIcon()
        icon_pause.addPixmap(QPixmap("icon/暂停.png"), QIcon.Normal, QIcon.Off)
        self.pause_action.setIcon(icon_pause)
        self.pause_action.setText("暂停")
        self.pause_action.triggered.connect(self.on_pause_action_clicked)

        self.stop_action = QAction(self)
        icon_stop = QIcon()
        icon_stop.addPixmap(QPixmap("icon/停止.png"), QIcon.Normal, QIcon.Off)
        self.stop_action.setIcon(icon_stop)
        self.stop_action.setText("停止")
        self.stop_action.triggered.connect(self.on_stop_action_clicked)

        self.save_action = QAction(self)
        icon_save = QIcon()
        icon_save.addPixmap(QPixmap("icon/保存.svg"), QIcon.Normal, QIcon.Off)
        self.save_action.setIcon(icon_save)
        self.save_action.setText("保存")
        self.save_action.triggered.connect(self.on_save_action_clicked)

        self.open_action = QAction(self)
        icon_open = QIcon()
        icon_open.addPixmap(QPixmap("icon/打开.svg"), QIcon.Normal, QIcon.Off)
        self.open_action.setIcon(icon_open)
        self.open_action.setText("打开")
        self.open_action.triggered.connect(self.on_open_action_clicked)

        self.trace_action = QAction(self)
        icon_trace = QIcon()
        icon_trace.addPixmap(QPixmap("icon/wink.svg"), QIcon.Normal, QIcon.Off)
        self.trace_action.setIcon(icon_trace)
        self.trace_action.setText("跟踪此流")
        self.trace_action.triggered.connect(self.on_trace_action_clicked)

        self.stoptrace_action = QAction(self)
        icon_stoptrace = QIcon()
        icon_stoptrace.addPixmap(QPixmap("icon/embarrassed.svg"), QIcon.Normal, QIcon.Off)
        self.stoptrace_action.setIcon(icon_stoptrace)
        self.stoptrace_action.setText("停止跟踪")
        self.stoptrace_action.triggered.connect(self.on_stoptrace_action_clicked)

        self.mainToolBar.addAction(self.start_action)
        # self.mainToolBar.setIconSize(QSize(30,30))
        self.mainToolBar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.mainToolBar.addSeparator()
        self.mainToolBar.addSeparator()
        self.mainToolBar.addAction(self.pause_action)
        self.mainToolBar.addSeparator()
        self.mainToolBar.addSeparator()
        self.mainToolBar.addAction(self.stop_action)
        self.mainToolBar.addSeparator()
        self.mainToolBar.addSeparator()
        self.mainToolBar.addAction(self.save_action)
        self.mainToolBar.addSeparator()
        self.mainToolBar.addSeparator()
        self.mainToolBar.addAction(self.open_action)
        self.mainToolBar.addSeparator()
        self.mainToolBar.addSeparator()
        self.mainToolBar.addAction(self.trace_action)
        self.mainToolBar.addSeparator()
        self.mainToolBar.addSeparator()
        self.mainToolBar.addAction(self.stoptrace_action)

        self.stop_action.setDisabled(True)
        self.pause_action.setDisabled(True)
        self.trace_action.setDisabled(True)
        self.stoptrace_action.setDisabled(True)
        self.save_action.setDisabled(True)

        font.setFamily("Courier")
        font.setBold(0.5)
        font.setPointSize(20)

        self.Filter = QLineEdit(self.Widget)
        self.Filter.setPlaceholderText("请使用BPF规则语法，否则没有输出")
        self.Filter.setStyleSheet("background:white")
        self.Filter.setFont(font)
        self.headLayout.addWidget(self.Filter)

        #过滤器按钮
        self.FilterButton = QPushButton(self.Widget)
        icon_filter = QIcon()
        icon_filter.addPixmap(QPixmap("icon/箭头.svg"), QIcon.Normal, QIcon.Off)
        self.FilterButton.setIcon(icon_filter)
        self.FilterButton.setIconSize(QSize(20, 20))
        self.FilterButton.clicked.connect(self.on_start_action_clicked)
        self.headLayout.addWidget(self.FilterButton)
        self.gridLayout.addLayout(self.headLayout, 0, 0, 1, 1)

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


    def save_file(self):
        if self.sniffer.pkt_id <= 1:
            return
        reply = QMessageBox.question(
                None,
                "提示",
                "是否保存已抓取的数据包？",
                QMessageBox.Yes,
                QMessageBox.Cancel,
            )
        if reply == QMessageBox.Yes:
            if self.sniffer.pkt_id == 1:
                QMessageBox.warning(None, "警告", "没有可保存的数据包！")
                return
            filename, _ = QFileDialog.getSaveFileName(
                parent=None,
                caption="保存文件",
                directory=os.getcwd(),
                filter="All Files (*);;Pcap Files (*.pcap)",
            )
            vaild_name = True
            if filename.find(".pcap") != -1:
                pass
            elif "." in filename:
                vaild_name = False
            if filename == "":
                return
            if vaild_name==False:
                QMessageBox.warning(None, "警告", "无效文件名！")
                return
            if filename.find(".pcap") == -1:
                filename = filename + ".pcap"

            shutil.copy(self.sniffer.tmp_file, filename)
            os.chmod(filename, 0o0777)
            QMessageBox.information(None, "提示", "保存成功！")
        
        self.sniffer.save_flag = 1


    def on_start_action_clicked(self):
        self.pause_action.setEnabled(True)
        self.stop_action.setEnabled(True)
        self.start_action.setDisabled(True)
        self.Filter.setDisabled(True)
        self.FilterButton.setDisabled(True)
        self.save_action.setDisabled(True)
        self.open_action.setDisabled(True)
        if self.timer.isActive() == False:
            self.timer.start()

        if self.sniffer.run_state != State.PAUSE:
            self.overviewTree.clear()
            self.pktWidget.clear()
            self.hexBrowser.setText("")
            # self.set_hex_text("")
        if self.Filter.text() == "":
            filters=None
        else:
            filters=self.Filter.text()

        self.sniffer.push_start(filters=filters)



    def on_pause_action_clicked(self):
        self.pause_action.setDisabled(True)
        self.stop_action.setEnabled(True)
        self.start_action.setEnabled(True)
        self.Filter.setDisabled(True)
        self.FilterButton.setDisabled(True)
        self.save_action.setEnabled(True)
        self.open_action.setDisabled(True)
        self.timer.stop()
        
        self.sniffer.push_pause()


    def on_stop_action_clicked(self):
        self.pause_action.setDisabled(True)
        self.stop_action.setDisabled(True)
        self.start_action.setEnabled(True)
        self.Filter.setEnabled(True)
        self.FilterButton.setEnabled(True)
        self.save_action.setEnabled(True)
        self.open_action.setEnabled(True)
        self.timer.stop()

        self.sniffer.push_stop()


    def on_save_action_clicked(self):
        self.save_file()

    def on_open_action_clicked(self):
        reply = QMessageBox.question(
                None,
                "提示",
                "清先设置过滤规则",
                QMessageBox.Ignore,
                QMessageBox.Cancel,
            )
        if reply == QMessageBox.Cancel:
            return
        self.pause_action.setDisabled(True)
        self.stop_action.setDisabled(True)
        self.start_action.setEnabled(True)
        self.Filter.setEnabled(True)
        self.FilterButton.setDisabled(True)
        self.save_action.setDisabled(True)
        self.open_action.setEnabled(True)

        self.save_file()
        self.overviewTree.clear()
        self.pktWidget.clear()
        self.hexBrowser.setText("")

        self.timer.stop()

        filename, _ = QFileDialog.getOpenFileName(
            parent=None,
            caption="打开文件",
            directory=os.getcwd(),
            filter="All Files (*);;Pcap Files (*.pcap)",
        )
        print(filename)
        if filename == "":
            return
        if filename:
            filters = None
            try:
                self.sniffer.read_packet(filename, filters=self.Filter.text())
            except:
                QMessageBox.warning(None, "警告", "不能打开此文件！")
                return

    def on_trace_action_clicked(self):
        pkt_id = self.overviewTree.currentItem().text(0)
        self.overviewTree.clear()
        self.trace_action.setDisabled(True)
        self.stoptrace_action.setEnabled(True)
        self.sniffer.push_trace(int(pkt_id))


    def on_stoptrace_action_clicked(self):
        self.overviewTree.clear()
        self.trace_action.setDisabled(True)
        self.stoptrace_action.setDisabled(True)
        self.sniffer.cancel_trace()


    def on_tableview_clicked(self):
        pkt_id = self.overviewTree.currentItem().text(0)

        if pkt_id and pkt_id.isdigit():
            # self.timer.stop()

            result, content = self.sniffer.parse_pkt_detail(int(pkt_id))
            sport = self.sniffer.pkt_list[int(pkt_id) - 1][7]
            dport = self.sniffer.pkt_list[int(pkt_id) - 1][8]
            if sport > 0 and dport > 0 and self.sniffer.trace_flag == False:
                # trace action
                self.trace_action.setEnabled(True)
                self.stoptrace_action.setDisabled(True)
            
            self.pktWidget.clear()
            for item in result:
                tmp_result = QTreeWidgetItem(self.pktWidget)
                tmp_result.setBackground(0 ,QBrush(QColor("#f5f2f2")))
                tmp_result.setText(0, item[0])
                for detail_info in item[1]:
                    ttmp = QTreeWidgetItem(tmp_result)
                    ttmp.setText(0, detail_info)
            self.hexBrowser.clear()
            self.hexBrowser.setText(content)


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