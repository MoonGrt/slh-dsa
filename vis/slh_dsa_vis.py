import sys, os, json
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QFileDialog, QTreeWidget,
    QTreeWidgetItem, QTextEdit, QGraphicsView, QGraphicsScene,
    QGraphicsEllipseItem, QGraphicsTextItem, QGraphicsLineItem,
)
from PyQt5.QtGui import (
    QPen, QBrush, QColor,
)
from PyQt5.QtCore import Qt

DEFAULT_JSON_PATH="/mnt/hgfs/share/slh-dsa/vis/trace.json"

# =========================================
# Graph constants
# =========================================

NODE_WIDTH = 120
NODE_HEIGHT = 40
X_SPACING = 180
Y_SPACING = 100


# =========================================
# Custom graphics node
# =========================================

class GraphNode(QGraphicsEllipseItem):
    def __init__(self, x, y, width, height, node_data, path, graph_view):
        super().__init__(x, y, width, height)
        self.node_data = node_data
        self.path = path
        self.graph_view = graph_view
        self.default_brush = QBrush(Qt.white)
        self.highlight_brush = QBrush(QColor(255, 255, 100))
        self.step_brush = QBrush(QColor(255, 170, 100))
        self.setBrush(self.default_brush)
        self.setPen(QPen(Qt.black, 2))

    def mousePressEvent(self, event):
        # Left click
        if event.button() == Qt.LeftButton:
            self.graph_view.main_window.select_graph_node(self.path)
        # Right click
        elif event.button() == Qt.RightButton:
            self.graph_view.main_window.toggle_tree_node(self.path)
        event.accept()

    def set_highlight(self, enabled):
        if enabled:
            self.setBrush(self.highlight_brush)
        else:
            self.setBrush(self.default_brush)

    def set_step_highlight(self, enabled):
        if enabled:
            self.setBrush(self.step_brush)
        else:
            self.setBrush(self.default_brush)


# =========================================
# Graph view
# =========================================

class TreeGraphView(QGraphicsView):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        self.positions = {}
        self.current_x = 0
        self.node_items = {}

    def redraw(self, root_node, expanded_paths):
        self.scene.clear()
        self.positions.clear()
        self.node_items.clear()
        self.current_x = 0
        visible_tree = self.build_visible_tree(
            root_node, expanded_paths, ()
        )
        self.calculate_positions(visible_tree, 0)
        self.draw_tree(visible_tree)

    def build_visible_tree(self, node, expanded_paths, path):
        visible_node = {"node": node, "path": path, "children": []}
        children = node.get("children", [])
        if path in expanded_paths:
            for index, child in enumerate(children):
                child_path = path + (index,)
                visible_child = self.build_visible_tree(
                    child, expanded_paths, child_path
                )
                visible_node["children"].append(visible_child)
        return visible_node

    def calculate_positions(self,visible_node,depth):
        children = visible_node["children"]
        if not children:
            x = self.current_x
            self.current_x += X_SPACING
        else:
            child_x_list = []
            for child in children:
                child_x = self.calculate_positions(child,depth + 1)
                child_x_list.append(child_x)
            x = sum(child_x_list) / len(child_x_list)
        y = depth * Y_SPACING
        self.positions[id(visible_node)] = (x, y)
        return x

    def draw_tree(self, visible_node):
        x, y = self.positions[id(visible_node)]
        node = visible_node["node"]
        path = visible_node["path"]
        name = self.get_node_name(node)
        # Create graph node
        graph_node = GraphNode(x, y, NODE_WIDTH, NODE_HEIGHT, node, path, self)
        self.scene.addItem(graph_node)
        self.node_items[path] = graph_node
        # Draw text
        text_item = QGraphicsTextItem(name)
        text_item.setPos(x + 10,y + 8)
        self.scene.addItem(text_item)
        # Draw children
        for child in visible_node["children"]:
            child_x, child_y = self.positions[id(child)]
            line = QGraphicsLineItem(
                x + NODE_WIDTH / 2,
                y + NODE_HEIGHT,
                child_x + NODE_WIDTH / 2,
                child_y
            )
            line.setPen(QPen(Qt.black, 2))
            self.scene.addItem(line)
            self.draw_tree(child)

    def get_node_name(self, node):
        info = node.get("info", {})
        if "name" in info:
            return info["name"]
        if "tag" in info:
            return info["tag"]
        return "node"


# =========================================
# Main window
# =========================================

class JsonViewer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("JSON Tree Viewer")
        self.resize(1800, 1000)
        self.root_json = None
        self.selected_path = None
        self.current_step = 0
        self.step_nodes = {}
        self.path_to_item = {}
        self.init_ui()
        self.auto_load()

    # =====================================
    # UI
    # =====================================

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        # =================================
        # Top buttons
        # =================================
        top_layout = QHBoxLayout()
        self.load_button = QPushButton("Load")
        self.load_button.clicked.connect(self.load_json_file)
        self.step_button = QPushButton("Step")
        self.step_button.clicked.connect(self.step_run)
        self.reset_button = QPushButton("Reset")
        self.reset_button.clicked.connect(self.reset_steps)
        top_layout.addWidget(self.load_button)
        top_layout.addWidget(self.step_button)
        top_layout.addWidget(self.reset_button)
        top_layout.addStretch()
        main_layout.addLayout(top_layout)

        # =================================
        # Main content
        # =================================
        content_layout = QHBoxLayout()
        # Left layout
        left_layout = QVBoxLayout()
        # Tree widget
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(["Nodes"])
        self.tree_widget.itemClicked.connect(self.on_tree_item_clicked)
        self.tree_widget.itemExpanded.connect(self.on_tree_expand_changed)
        self.tree_widget.itemCollapsed.connect(self.on_tree_expand_changed)
        # Detail panel
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        left_layout.addWidget(self.tree_widget, 3)
        left_layout.addWidget(self.detail_text, 2)
        # Graph view
        self.graph_view = TreeGraphView(self)
        content_layout.addLayout(left_layout, 3)
        content_layout.addWidget(self.graph_view, 7)
        main_layout.addLayout(content_layout)

    # =====================================
    # Load JSON
    # =====================================
    def auto_load(self):
        if os.path.exists(DEFAULT_JSON_PATH):
            with open(
                DEFAULT_JSON_PATH, "r", encoding="utf-8"
            ) as f:
                self.root_json=json.load(f)
            self.after_load_json()

    def load_json_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open JSON File",
            DEFAULT_JSON_PATH, "JSON Files (*.json)"
        )
        if not file_path:
            return
        with open(file_path, "r", encoding="utf-8") as f:
            self.root_json = json.load(f)
        self.after_load_json()

    def after_load_json(self):
        self.current_step=0
        self.step_nodes.clear()
        self.path_to_item.clear()
        self.collect_step_nodes(self.root_json,())
        self.build_tree()

    # =====================================
    # Build tree widget
    # =====================================
    def build_tree(self):
        self.tree_widget.clear()
        root_name = self.get_node_name(self.root_json)
        root_item = QTreeWidgetItem([root_name])
        root_item.setData(0, Qt.UserRole, self.root_json)
        root_item.setData(0, Qt.UserRole + 1, ())
        self.path_to_item[()] = root_item
        self.tree_widget.addTopLevelItem(root_item)
        self.add_children(root_item, self.root_json, ())
        root_item.setExpanded(False)
        self.update_graph()

    def add_children(self, parent_item, node, parent_path):
        children = node.get("children", [])
        for index, child in enumerate(children):
            child_path = parent_path + (index,)
            child_name = self.get_node_name(child)
            item = QTreeWidgetItem([child_name])
            item.setData(0, Qt.UserRole, child)
            item.setData(0, Qt.UserRole + 1, child_path)
            self.path_to_item[child_path] = item
            parent_item.addChild(item)
            self.add_children(item, child, child_path )
            item.setExpanded(False)

    # =====================================
    # Update graph
    # =====================================
    def update_graph(self):
        if not self.root_json:
            return
        expanded_paths = self.get_expanded_paths()
        self.graph_view.redraw(self.root_json, expanded_paths)
        self.update_selected_highlight()

    def get_expanded_paths(self):
        expanded = set()
        def walk(item):
            path = item.data(0, Qt.UserRole + 1)
            if item.isExpanded():
                expanded.add(path)
            for i in range(item.childCount()):
                walk(item.child(i))
        root = self.tree_widget.topLevelItem(0)
        if root:
            walk(root)
        return expanded

    # =====================================
    # Tree events
    # =====================================
    def on_tree_expand_changed(self, item):
        self.update_graph()

    def on_tree_item_clicked(self, item, column):
        path = item.data(0, Qt.UserRole + 1)
        self.select_graph_node(path)

    # =====================================
    # Node selection
    # =====================================
    def select_graph_node(self, path):
        self.selected_path = path
        item = self.path_to_item.get(path)
        if item:
            self.tree_widget.setCurrentItem(item)
            node = item.data(0, Qt.UserRole)
            self.show_node_detail(node)
        self.update_selected_highlight()

    def update_selected_highlight(self):
        for path, graph_node in self.graph_view.node_items.items():
            graph_node.set_highlight(path == self.selected_path)

    # =====================================
    # Detail panel
    # =====================================
    def show_node_detail(self, node):
        info = node.get("info", {})
        data = node.get("data", {})
        text = ""
        text += "=== INFO ===\n"
        text += json.dumps(info, indent=4, ensure_ascii=False)
        text += "\n\n=== DATA ===\n"
        text += json.dumps(data, indent=4, ensure_ascii=False)
        self.detail_text.setText(text)

    # =====================================
    # Expand/collapse sync
    # =====================================
    def toggle_tree_node(self, path):
        item = self.path_to_item.get(path)
        if not item:
            return
        item.setExpanded(not item.isExpanded())
        self.update_graph()

    # =====================================
    # Step handling
    # =====================================
    def collect_step_nodes(self, node, path):
        info = node.get("info", {})
        if "step" in info:
            step = info["step"]
            self.step_nodes[step] = path
        children = node.get("children", [])
        for index, child in enumerate(children):
            child_path = path + (index,)
            self.collect_step_nodes(child, child_path)

    def step_run(self):
        self.current_step += 1
        if self.current_step not in self.step_nodes:
            return
        target_path = self.step_nodes[self.current_step]
        visible_path = self.find_visible_path(target_path)
        self.select_graph_node(visible_path)
        graph_node = self.graph_view.node_items.get(visible_path)
        if graph_node:
            graph_node.set_step_highlight(True)

    def reset_steps(self):
        self.current_step = 0
        self.selected_path = None
        self.update_graph()

    def find_visible_path(self, path):
        expanded = self.get_expanded_paths()
        current = path
        while current:
            parent = current[:-1]
            if parent not in expanded:
                current = parent
            else:
                break
        return current

    # =====================================
    # Utility
    # =====================================
    def get_node_name(self, node):
        info = node.get("info", {})
        if "name" in info:
            return info["name"]
        if "tag" in info:
            return info["tag"]
        return "node"


# =========================================
# Main
# =========================================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    viewer = JsonViewer()
    viewer.show()
    sys.exit(app.exec_())
