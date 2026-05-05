import sys
import hashlib
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QGraphicsView, QGraphicsScene, QGraphicsRectItem, QGraphicsTextItem
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPen, QBrush, QColor, QFont

class MerkleTreeDemo(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Merkle Tree Step-by-Step Visualizer")
        self.resize(900, 650)

        self.layout = QVBoxLayout()

        self.view = QGraphicsView()
        self.scene = QGraphicsScene()
        self.view.setScene(self.scene)
        self.view.setRenderHint
        self.layout.addWidget(self.view)

        self.button = QPushButton("Next Step")
        self.button.clicked.connect(self.next_step)
        self.layout.addWidget(self.button)

        self.setLayout(self.layout)

        self.data = ["a", "b", "c", "d"]
        self.levels = []
        self.node_items = []

        self.traversal = []  # (level, index)
        self.step_ptr = 0

        self.build_tree()
        self.build_traversal()
        self.draw_tree()

    def hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()[:8]

    def build_tree(self):
        leaves = [self.hash(d) for d in self.data]
        self.levels.append(leaves)

        current = leaves
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i+1] if i+1 < len(current) else left
                next_level.append(self.hash(left + right))
            self.levels.append(next_level)
            current = next_level

    def build_traversal(self):
        # level-by-level, left-to-right node traversal
        for l, level in enumerate(self.levels):
            for i in range(len(level)):
                self.traversal.append((l, i))

    def draw_tree(self):
        self.scene.clear()
        self.node_items = []

        node_w = 70
        node_h = 35
        x_gap = 140
        y_gap = 110

        max_width = len(self.levels[0])

        for l, level in enumerate(self.levels):
            row = []
            y = l * y_gap

            start_x = (max_width - len(level)) * x_gap / 2

            for i, val in enumerate(level):
                x = start_x + i * x_gap

                rect = QGraphicsRectItem(x, y, node_w, node_h)

                rect.setPen(QPen(Qt.black, 2))
                rect.setBrush(QBrush(QColor(245, 245, 245)))

                text = QGraphicsTextItem(str(i))
                text.setFont(QFont("Arial", 12))
                text.setDefaultTextColor(Qt.black)
                text.setPos(x + node_w/3, y + 5)

                self.scene.addItem(rect)
                self.scene.addItem(text)

                row.append(rect)

            self.node_items.append(row)

        # edges
        pen = QPen(QColor(180, 180, 180))
        for l in range(len(self.node_items) - 1):
            for i, parent in enumerate(self.node_items[l + 1]):
                left = self.node_items[l][i * 2]
                right = self.node_items[l][i * 2 + 1] if i * 2 + 1 < len(self.node_items[l]) else left

                p_parent = parent.rect().center() + parent.pos()
                p_left = left.rect().center() + left.pos()
                p_right = right.rect().center() + right.pos()

                self.scene.addLine(p_left.x(), p_left.y(), p_parent.x(), p_parent.y(), pen)
                self.scene.addLine(p_right.x(), p_right.y(), p_parent.x(), p_parent.y(), pen)

    def reset_colors(self):
        for row in self.node_items:
            for node in row:
                node.setBrush(QBrush(QColor(245, 245, 245)))

    def highlight_node(self, level, index):
        self.reset_colors()
        node = self.node_items[level][index]
        node.setBrush(QBrush(QColor(255, 180, 60)))

    def next_step(self):
        if self.step_ptr >= len(self.traversal):
            return
        level, idx = self.traversal[self.step_ptr]
        self.highlight_node(level, idx)
        self.step_ptr += 1


if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = MerkleTreeDemo()
    w.show()
    sys.exit(app.exec_())