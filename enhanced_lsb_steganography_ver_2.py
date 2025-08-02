import sys
import os
import numpy as np
from matplotlib import pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QSplitter, QFileDialog, QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal
from PIL import Image
import time
import json
import warnings

# Import các class từ file enhanced_lsb_steganography.py
from enhanced_lsb_steganography import (
    EnhancedLSBSteganography,
    TraditionalLSB,
    SecurityTester,
    ComparativeAnalysis,
    create_test_image
)

warnings.filterwarnings('ignore')


class SteganographyWorker(QThread):
    """Worker thread để xử lý steganography không blocking GUI"""
    finished = pyqtSignal(dict)
    progress = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, operation, params):
        super().__init__()
        self.operation = operation
        self.params = params

    def run(self):
        try:
            if self.operation == 'embed':
                self.embed_process()
            elif self.operation == 'extract':
                self.extract_process()
            elif self.operation == 'compare':
                self.compare_process()
            elif self.operation == 'security_test':
                self.security_test_process()
        except Exception as e:
            self.error.emit(str(e))

    def embed_process(self):
        self.progress.emit("Đang khởi tạo steganography engine...")
        engine = EnhancedLSBSteganography()

        self.progress.emit("Đang embedding message...")
        start_time = time.time()

        stego_array = engine.embed_message(
            self.params['image_path'],
            self.params['message'],
            self.params['key'],
            self.params['output_path']
        )

        embed_time = time.time() - start_time

        if stego_array is not None:
            # Calculate metrics
            self.progress.emit("Đang tính toán metrics...")
            original_img = np.array(Image.open(self.params['image_path']))
            psnr = engine.calculate_psnr(original_img, stego_array)
            mse = engine.calculate_mse(original_img, stego_array)

            capacity = engine.get_embedding_capacity(self.params['image_path'])

            result = {
                'status': 'success',
                'stego_array': stego_array,
                'original_array': original_img,
                'embed_time': embed_time,
                'psnr': psnr,
                'mse': mse,
                'capacity': capacity,
                'message_length': len(self.params['message'])
            }
        else:
            result = {'status': 'error', 'message': 'Embedding failed'}

        self.finished.emit(result)

    def extract_process(self):
        self.progress.emit("Đang extract message...")
        engine = EnhancedLSBSteganography()

        start_time = time.time()
        extracted_message = engine.extract_message(
            self.params['stego_path'],
            self.params['key']
        )
        extract_time = time.time() - start_time

        result = {
            'status': 'success' if extracted_message is not None else 'error',
            'extracted_message': extracted_message,
            'extract_time': extract_time,
            'original_message': self.params.get('original_message', '')
        }

        self.finished.emit(result)

    def compare_process(self):
        self.progress.emit("Đang so sánh Traditional vs Enhanced LSB...")

        analyzer = ComparativeAnalysis()
        results = analyzer.comprehensive_comparison(
            [self.params['image_path']],
            [self.params['message']],
            self.params['key']
        )

        result = {
            'status': 'success',
            'comparison_results': results
        }

        self.finished.emit(result)

    def security_test_process(self):
        self.progress.emit("Đang thực hiện security analysis...")

        engine = EnhancedLSBSteganography()
        security_tester = SecurityTester(engine)

        # Chi-square test
        self.progress.emit("Chi-square test...")
        chi_square_result = security_tester.chi_square_test(self.params['stego_array'])

        # Histogram analysis
        self.progress.emit("Histogram analysis...")
        histogram_result = security_tester.histogram_analysis(
            self.params['original_array'],
            self.params['stego_array']
        )

        # Brute force test (limited)
        self.progress.emit("Brute force resistance test...")
        bf_result = security_tester.brute_force_resistance_test(
            self.params['stego_path'],
            self.params['key'],
            100  # Limited for GUI
        )

        result = {
            'status': 'success',
            'chi_square': chi_square_result,
            'histogram': histogram_result,
            'brute_force': bf_result
        }

        self.finished.emit(result)


class PlotCanvas(FigureCanvas):
    """Canvas để hiển thị matplotlib plots"""

    def __init__(self, parent=None, width=8, height=6, dpi=100):
        self.figure = Figure(figsize=(width, height), dpi=dpi)
        super().__init__(self.figure)
        self.setParent(parent)


class SteganographyGUI(QtWidgets.QMainWindow):
    """Ứng dụng PyQt5 cho Enhanced LSB Steganography"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enhanced LSB Steganography Explorer")
        self.resize(1800, 1200)

        # Data holders
        self.cover_image_path = None
        self.stego_image_path = None
        self.current_message = ""
        self.current_key = ""
        self.stego_array = None
        self.original_array = None
        self.worker = None

        self.setup_ui()

    def setup_ui(self):
        """Thiết lập giao diện người dùng"""
        central = QtWidgets.QWidget(self)
        self.setCentralWidget(central)
        main_layout = QtWidgets.QVBoxLayout(central)

        # === HEADER ===
        header_label = QtWidgets.QLabel("🔒 ENHANCED LSB STEGANOGRAPHY TOOL")
        header_label.setAlignment(QtCore.Qt.AlignCenter)
        header_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #2c3e50;
                padding: 10px;
                background-color: #ecf0f1;
                border-radius: 5px;
                margin: 5px;
            }
        """)
        main_layout.addWidget(header_label)

        # === INPUT SECTION ===
        input_group = QtWidgets.QGroupBox("1. 📂 Dữ liệu đầu vào")
        input_layout = QtWidgets.QVBoxLayout(input_group)

        # Image selection
        image_layout = QtWidgets.QHBoxLayout()
        self.image_line = QtWidgets.QLineEdit()
        self.image_line.setReadOnly(True)
        self.image_line.setPlaceholderText("Chọn ảnh cover...")

        browse_btn = QtWidgets.QPushButton("📁 Chọn ảnh")
        browse_btn.clicked.connect(self.browse_image)

        create_test_btn = QtWidgets.QPushButton("🎨 Tạo ảnh test")
        create_test_btn.clicked.connect(self.create_test_image)

        image_layout.addWidget(QtWidgets.QLabel("Cover Image:"))
        image_layout.addWidget(self.image_line)
        image_layout.addWidget(browse_btn)
        image_layout.addWidget(create_test_btn)

        input_layout.addLayout(image_layout)

        # Message input
        message_layout = QtWidgets.QVBoxLayout()
        message_layout.addWidget(QtWidgets.QLabel("📝 Secret Message:"))

        self.message_text = QtWidgets.QTextEdit()
        self.message_text.setMaximumHeight(100)
        self.message_text.setPlaceholderText("Nhập message cần giấu...")

        message_layout.addWidget(self.message_text)
        input_layout.addLayout(message_layout)

        # Key input
        key_layout = QtWidgets.QHBoxLayout()
        self.key_line = QtWidgets.QLineEdit()
        self.key_line.setPlaceholderText("Nhập secret key...")

        generate_key_btn = QtWidgets.QPushButton("🔑 Random Key")
        generate_key_btn.clicked.connect(self.generate_random_key)

        key_layout.addWidget(QtWidgets.QLabel("🔐 Secret Key:"))
        key_layout.addWidget(self.key_line)
        key_layout.addWidget(generate_key_btn)

        input_layout.addLayout(key_layout)

        main_layout.addWidget(input_group)

        # === OPERATIONS SECTION ===
        ops_group = QtWidgets.QGroupBox("2. 🚀 Thao tác")
        ops_layout = QtWidgets.QHBoxLayout(ops_group)

        # Embed button
        self.embed_btn = QtWidgets.QPushButton("📥 Embed Message")
        self.embed_btn.clicked.connect(self.embed_message)
        self.embed_btn.setStyleSheet(
            "QPushButton { background-color: #3498db; color: white; padding: 8px; font-weight: bold; }")

        # Extract button
        self.extract_btn = QtWidgets.QPushButton("📤 Extract Message")
        self.extract_btn.clicked.connect(self.extract_message)
        self.extract_btn.setEnabled(False)
        self.extract_btn.setStyleSheet(
            "QPushButton { background-color: #e74c3c; color: white; padding: 8px; font-weight: bold; }")

        # Compare button
        self.compare_btn = QtWidgets.QPushButton("⚖️ Compare Methods")
        self.compare_btn.clicked.connect(self.compare_methods)
        self.compare_btn.setStyleSheet(
            "QPushButton { background-color: #f39c12; color: white; padding: 8px; font-weight: bold; }")

        # Security test button
        self.security_btn = QtWidgets.QPushButton("🔍 Security Analysis")
        self.security_btn.clicked.connect(self.security_analysis)
        self.security_btn.setEnabled(False)
        self.security_btn.setStyleSheet(
            "QPushButton { background-color: #9b59b6; color: white; padding: 8px; font-weight: bold; }")

        ops_layout.addWidget(self.embed_btn)
        ops_layout.addWidget(self.extract_btn)
        ops_layout.addWidget(self.compare_btn)
        ops_layout.addWidget(self.security_btn)

        main_layout.addWidget(ops_group)

        # === PROGRESS BAR ===
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        self.status_label = QtWidgets.QLabel("📊 Sẵn sàng...")
        main_layout.addWidget(self.status_label)

        # === RESULTS SECTION ===
        results_splitter = QSplitter(QtCore.Qt.Horizontal)

        # Left panel - Text results
        left_widget = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_widget)

        self.text_tabs = QtWidgets.QTabWidget()

        # Tab 1: Basic Results
        self.basic_results_text = QtWidgets.QTextEdit()
        self.basic_results_text.setReadOnly(True)
        self.text_tabs.addTab(self.basic_results_text, "📋 Kết quả cơ bản")

        # Tab 2: Security Analysis
        self.security_results_text = QtWidgets.QTextEdit()
        self.security_results_text.setReadOnly(True)
        self.text_tabs.addTab(self.security_results_text, "🔐 Phân tích bảo mật")

        # Tab 3: Comparison
        self.comparison_results_text = QtWidgets.QTextEdit()
        self.comparison_results_text.setReadOnly(True)
        self.text_tabs.addTab(self.comparison_results_text, "⚖️ So sánh phương pháp")

        # Tab 4: Image Info
        self.image_info_text = QtWidgets.QTextEdit()
        self.image_info_text.setReadOnly(True)
        self.text_tabs.addTab(self.image_info_text, "🖼️ Thông tin ảnh")

        left_layout.addWidget(self.text_tabs)
        results_splitter.addWidget(left_widget)

        # Right panel - Visualizations
        right_widget = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_widget)

        self.viz_tabs = QtWidgets.QTabWidget()

        # Tab 1: Image Comparison
        self.image_canvas = PlotCanvas()
        self.viz_tabs.addTab(self.image_canvas, "🖼️ So sánh ảnh")

        # Tab 2: Metrics
        self.metrics_canvas = PlotCanvas()
        self.viz_tabs.addTab(self.metrics_canvas, "📊 Metrics")

        # Tab 3: Security Charts
        self.security_canvas = PlotCanvas()
        self.viz_tabs.addTab(self.security_canvas, "🔍 Phân tích bảo mật")

        # Tab 4: Comparison Charts
        self.comparison_canvas = PlotCanvas()
        self.viz_tabs.addTab(self.comparison_canvas, "📈 Biểu đồ so sánh")

        right_layout.addWidget(self.viz_tabs)
        results_splitter.addWidget(right_widget)

        main_layout.addWidget(results_splitter)

        # Set splitter ratio
        results_splitter.setSizes([600, 800])

    def browse_image(self):
        """Chọn ảnh cover"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Chọn ảnh cover", "",
            "Image Files (*.png *.jpg *.jpeg *.bmp *.tiff);;All Files (*)"
        )

        if file_path:
            self.cover_image_path = file_path
            self.image_line.setText(file_path)
            self.analyze_image(file_path)
            self.status_label.setText(f"✅ Đã load ảnh: {os.path.basename(file_path)}")

    def create_test_image(self):
        """Tạo ảnh test"""
        try:
            test_path = create_test_image(512, 512, "gui_test_image.png")
            self.cover_image_path = test_path
            self.image_line.setText(test_path)
            self.analyze_image(test_path)
            self.status_label.setText("✅ Đã tạo ảnh test")
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Không thể tạo ảnh test: {str(e)}")

    def generate_random_key(self):
        """Sinh key ngẫu nhiên"""
        import random
        import string

        key_length = 16
        characters = string.ascii_letters + string.digits
        random_key = ''.join(random.choices(characters, k=key_length))
        self.key_line.setText(random_key)

    def analyze_image(self, image_path):
        """Phân tích thông tin ảnh"""
        try:
            img = Image.open(image_path)
            img_array = np.array(img)

            # Basic info
            info_text = f"🖼️ THÔNG TIN ẢNH\n"
            info_text += f"{'=' * 40}\n"
            info_text += f"📄 File: {os.path.basename(image_path)}\n"
            info_text += f"📐 Kích thước: {img_array.shape}\n"
            info_text += f"🎨 Mode: {img.mode}\n"
            info_text += f"📊 Data type: {img_array.dtype}\n"
            info_text += f"🔢 Min pixel: {img_array.min()}\n"
            info_text += f"🔢 Max pixel: {img_array.max()}\n"
            info_text += f"📈 Mean pixel: {img_array.mean():.2f}\n"

            # Capacity calculation
            engine = EnhancedLSBSteganography()
            capacity = engine.get_embedding_capacity(image_path)

            info_text += f"\n💽 EMBEDDING CAPACITY\n"
            info_text += f"{'=' * 30}\n"
            info_text += f"🔸 Max bits: {capacity['max_bits']:,}\n"
            info_text += f"🔸 Max characters: {capacity['max_characters']:,}\n"
            info_text += f"🔸 Overhead: {capacity['overhead_characters']} chars\n"

            # Histogram analysis
            if len(img_array.shape) == 3:
                info_text += f"\n🎨 CHANNEL ANALYSIS\n"
                info_text += f"{'=' * 25}\n"
                channels = ['Red', 'Green', 'Blue']
                for i, channel in enumerate(channels):
                    channel_data = img_array[:, :, i]
                    info_text += f"🔸 {channel}: mean={channel_data.mean():.1f}, std={channel_data.std():.1f}\n"

            self.image_info_text.setText(info_text)

            # Display image
            self.display_single_image(img_array, "Cover Image")

        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Không thể phân tích ảnh: {str(e)}")

    def display_single_image(self, img_array, title):
        """Hiển thị một ảnh"""
        try:
            self.image_canvas.figure.clear()
            ax = self.image_canvas.figure.add_subplot(111)

            ax.imshow(img_array)
            ax.set_title(title, fontsize=14, fontweight='bold')
            ax.axis('off')

            self.image_canvas.figure.tight_layout()
            self.image_canvas.draw()
        except Exception as e:
            print(f"Lỗi hiển thị ảnh: {e}")

    def embed_message(self):
        """Embed message vào ảnh"""
        if not self.cover_image_path:
            QMessageBox.warning(self, "Cảnh báo", "Vui lòng chọn ảnh cover")
            return

        message = self.message_text.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Cảnh báo", "Vui lòng nhập message")
            return

        key = self.key_line.text().strip()
        if not key:
            QMessageBox.warning(self, "Cảnh báo", "Vui lòng nhập secret key")
            return

        # Save current inputs
        self.current_message = message
        self.current_key = key

        # Setup output path
        output_path = "stego_output.png"
        self.stego_image_path = output_path

        # Start embedding process
        self.start_progress("Embedding...")

        params = {
            'image_path': self.cover_image_path,
            'message': message,
            'key': key,
            'output_path': output_path
        }

        self.worker = SteganographyWorker('embed', params)
        self.worker.finished.connect(self.on_embed_finished)
        self.worker.progress.connect(self.update_status)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_embed_finished(self, result):
        """Xử lý kết quả embedding"""
        self.stop_progress()

        if result['status'] == 'success':
            self.stego_array = result['stego_array']
            self.original_array = result['original_array']

            # Display results
            results_text = f"✅ EMBEDDING THÀNH CÔNG\n"
            results_text += f"{'=' * 40}\n"
            results_text += f"⏱️ Thời gian: {result['embed_time']:.3f} giây\n"
            results_text += f"📏 Message length: {result['message_length']} ký tự\n"
            results_text += f"📊 PSNR: {result['psnr']:.2f} dB\n"
            results_text += f"📊 MSE: {result['mse']:.4f}\n"
            results_text += f"💽 Capacity used: {result['message_length']}/{result['capacity']['max_characters']} chars "
            results_text += f"({result['message_length'] / result['capacity']['max_characters'] * 100:.2f}%)\n\n"

            quality = "Excellent" if result['psnr'] > 50 else "Good" if result['psnr'] > 40 else "Acceptable"
            results_text += f"🏆 Quality: {quality}\n"
            results_text += f"💾 Stego image saved: {self.stego_image_path}\n"

            self.basic_results_text.setText(results_text)

            # Display image comparison
            self.display_image_comparison(result['original_array'], result['stego_array'])

            # Plot metrics
            self.plot_metrics(result)

            # Enable other operations
            self.extract_btn.setEnabled(True)
            self.security_btn.setEnabled(True)

            self.status_label.setText("✅ Embedding hoàn thành!")

        else:
            QMessageBox.critical(self, "Lỗi", result.get('message', 'Embedding failed'))

    def display_image_comparison(self, original, stego):
        """Hiển thị so sánh ảnh"""
        try:
            self.image_canvas.figure.clear()

            # Create subplots
            ax1 = self.image_canvas.figure.add_subplot(131)
            ax2 = self.image_canvas.figure.add_subplot(132)
            ax3 = self.image_canvas.figure.add_subplot(133)

            # Original image
            ax1.imshow(original)
            ax1.set_title('Original Image', fontweight='bold')
            ax1.axis('off')

            # Stego image
            ax2.imshow(stego)
            ax2.set_title('Stego Image', fontweight='bold')
            ax2.axis('off')

            # Difference (amplified)
            diff = np.abs(original.astype(float) - stego.astype(float))
            diff_amplified = np.clip(diff * 10, 0, 255)
            ax3.imshow(diff_amplified.astype(np.uint8))
            ax3.set_title('Difference (10x amplified)', fontweight='bold')
            ax3.axis('off')

            self.image_canvas.figure.tight_layout()
            self.image_canvas.draw()

        except Exception as e:
            print(f"Lỗi hiển thị so sánh ảnh: {e}")

    def plot_metrics(self, result):
        """Vẽ biểu đồ metrics"""
        try:
            self.metrics_canvas.figure.clear()

            # Create subplots
            ax1 = self.metrics_canvas.figure.add_subplot(221)
            ax2 = self.metrics_canvas.figure.add_subplot(222)
            ax3 = self.metrics_canvas.figure.add_subplot(223)
            ax4 = self.metrics_canvas.figure.add_subplot(224)

            # PSNR gauge
            psnr = result['psnr']
            colors = ['red' if psnr < 30 else 'orange' if psnr < 40 else 'green']
            ax1.bar(['PSNR'], [psnr], color=colors)
            ax1.set_ylabel('dB')
            ax1.set_title(f'PSNR: {psnr:.2f} dB')
            ax1.grid(True, alpha=0.3)

            # MSE
            mse = result['mse']
            ax2.bar(['MSE'], [mse], color='skyblue')
            ax2.set_ylabel('MSE')
            ax2.set_title(f'MSE: {mse:.4f}')
            ax2.grid(True, alpha=0.3)

            # Capacity usage
            used = result['message_length']
            total = result['capacity']['max_characters']
            usage_percent = used / total * 100

            ax3.pie([used, total - used], labels=['Used', 'Available'], autopct='%1.1f%%',
                    colors=['lightcoral', 'lightgreen'])
            ax3.set_title(f'Capacity Usage\n{used}/{total} chars')

            # Processing time
            ax4.bar(['Embed Time'], [result['embed_time']], color='gold')
            ax4.set_ylabel('Seconds')
            ax4.set_title(f'Processing Time: {result["embed_time"]:.3f}s')
            ax4.grid(True, alpha=0.3)

            self.metrics_canvas.figure.tight_layout()
            self.metrics_canvas.draw()

        except Exception as e:
            print(f"Lỗi vẽ metrics: {e}")

    def extract_message(self):
        """Extract message từ stego image"""
        if not self.stego_image_path or not os.path.exists(self.stego_image_path):
            QMessageBox.warning(self, "Cảnh báo", "Không tìm thấy stego image")
            return

        key = self.key_line.text().strip()
        if not key:
            QMessageBox.warning(self, "Cảnh báo", "Vui lòng nhập secret key")
            return

        self.start_progress("Extracting...")

        params = {
            'stego_path': self.stego_image_path,
            'key': key,
            'original_message': self.current_message
        }

        self.worker = SteganographyWorker('extract', params)
        self.worker.finished.connect(self.on_extract_finished)
        self.worker.progress.connect(self.update_status)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_extract_finished(self, result):
        """Xử lý kết quả extraction"""
        self.stop_progress()

        if result['status'] == 'success':
            extracted = result['extracted_message']
            original = result['original_message']

            results_text = f"📤 EXTRACTION RESULTS\n"
            results_text += f"{'=' * 40}\n"
            results_text += f"⏱️ Extract time: {result['extract_time']:.3f} seconds\n\n"

            results_text += f"📝 ORIGINAL MESSAGE:\n"
            results_text += f"{'-' * 20}\n"
            results_text += f"{original}\n\n"

            results_text += f"📤 EXTRACTED MESSAGE:\n"
            results_text += f"{'-' * 20}\n"
            results_text += f"{extracted}\n\n"

            # Verification
            is_match = (extracted == original)
            results_text += f"✅ VERIFICATION:\n"
            results_text += f"{'-' * 15}\n"
            results_text += f"Match: {'✅ YES' if is_match else '❌ NO'}\n"

            if not is_match and extracted and original:
                # Calculate similarity
                similarity = self.calculate_text_similarity(original, extracted)
                results_text += f"Similarity: {similarity:.1f}%\n"

            current_text = self.basic_results_text.toPlainText()
            self.basic_results_text.setText(current_text + "\n\n" + results_text)

            self.status_label.setText("✅ Extraction hoàn thành!")

        else:
            QMessageBox.critical(self, "Lỗi", "Extraction failed")

    def calculate_text_similarity(self, text1, text2):
        """Tính độ tương đồng giữa 2 text"""
        if not text1 or not text2:
            return 0.0

        # Simple character-level similarity
        min_len = min(len(text1), len(text2))
        matches = sum(1 for i in range(min_len) if text1[i] == text2[i])

        return (matches / max(len(text1), len(text2))) * 100

    def compare_methods(self):
        """So sánh Traditional vs Enhanced LSB"""
        if not self.cover_image_path:
            QMessageBox.warning(self, "Cảnh báo", "Vui lòng chọn ảnh cover")
            return

        message = self.message_text.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Cảnh báo", "Vui lòng nhập message")
            return

        key = self.key_line.text().strip()
        if not key:
            key = "default_comparison_key"
            self.key_line.setText(key)

        self.start_progress("Comparing methods...")

        params = {
            'image_path': self.cover_image_path,
            'message': message,
            'key': key
        }

        self.worker = SteganographyWorker('compare', params)
        self.worker.finished.connect(self.on_compare_finished)
        self.worker.progress.connect(self.update_status)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_compare_finished(self, result):
        """Xử lý kết quả comparison"""
        self.stop_progress()

        if result['status'] == 'success':
            comparison = result['comparison_results']

            # Display text results
            results_text = f"⚖️ COMPARISON: TRADITIONAL vs ENHANCED LSB\n"
            results_text += f"{'=' * 60}\n\n"

            # Traditional results
            trad_analysis = comparison['detailed_analysis']['traditional']
            results_text += f"📊 TRADITIONAL LSB:\n"
            results_text += f"{'-' * 30}\n"
            results_text += f"Tests completed: {trad_analysis['total_tests']}\n"
            results_text += f"Average PSNR: {trad_analysis['avg_psnr']:.2f} dB\n"
            results_text += f"Average MSE: {trad_analysis['avg_mse']:.4f}\n"
            results_text += f"Average Chi-square: {trad_analysis['avg_chi_square']:.2f}\n"
            results_text += f"Success rate: {trad_analysis['success_rate'] * 100:.1f}%\n\n"

            # Enhanced results
            enh_analysis = comparison['detailed_analysis']['enhanced']
            results_text += f"🚀 ENHANCED LSB:\n"
            results_text += f"{'-' * 30}\n"
            results_text += f"Tests completed: {enh_analysis['total_tests']}\n"
            results_text += f"Average PSNR: {enh_analysis['avg_psnr']:.2f} dB\n"
            results_text += f"Average MSE: {enh_analysis['avg_mse']:.4f}\n"
            results_text += f"Average Chi-square: {enh_analysis['avg_chi_square']:.2f}\n"
            results_text += f"Success rate: {enh_analysis['success_rate'] * 100:.1f}%\n\n"

            # Improvements
            results_text += f"📈 IMPROVEMENTS (Enhanced vs Traditional):\n"
            results_text += f"{'-' * 45}\n"
            for metric, improvement in comparison['improvements'].items():
                emoji = "📈" if improvement > 0 else "📉"
                results_text += f"{emoji} {metric}: {improvement:+.1f}%\n"

            self.comparison_results_text.setText(results_text)

            # Plot comparison charts
            self.plot_comparison_charts(comparison)

            self.status_label.setText("✅ Comparison hoàn thành!")

        else:
            QMessageBox.critical(self, "Lỗi", "Comparison failed")

    def plot_comparison_charts(self, comparison):
        """Vẽ biểu đồ so sánh"""
        try:
            self.comparison_canvas.figure.clear()

            # Create subplots
            ax1 = self.comparison_canvas.figure.add_subplot(221)
            ax2 = self.comparison_canvas.figure.add_subplot(222)
            ax3 = self.comparison_canvas.figure.add_subplot(223)
            ax4 = self.comparison_canvas.figure.add_subplot(224)

            trad = comparison['detailed_analysis']['traditional']
            enh = comparison['detailed_analysis']['enhanced']

            # PSNR comparison
            methods = ['Traditional', 'Enhanced']
            psnr_values = [trad['avg_psnr'], enh['avg_psnr']]
            colors = ['lightblue', 'lightgreen']

            bars1 = ax1.bar(methods, psnr_values, color=colors)
            ax1.set_ylabel('PSNR (dB)')
            ax1.set_title('PSNR Comparison')
            ax1.grid(True, alpha=0.3)

            # Add values on bars
            for bar, value in zip(bars1, psnr_values):
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width() / 2., height + 0.5,
                         f'{value:.2f}', ha='center', va='bottom')

            # Chi-square comparison
            chi_values = [trad['avg_chi_square'], enh['avg_chi_square']]
            bars2 = ax2.bar(methods, chi_values, color=['lightcoral', 'lightsalmon'])
            ax2.set_ylabel('Chi-square')
            ax2.set_title('Chi-square Test (Lower = Better)')
            ax2.grid(True, alpha=0.3)

            for bar, value in zip(bars2, chi_values):
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width() / 2., height + 5,
                         f'{value:.1f}', ha='center', va='bottom')

            # MSE comparison
            mse_values = [trad['avg_mse'], enh['avg_mse']]
            bars3 = ax3.bar(methods, mse_values, color=['wheat', 'khaki'])
            ax3.set_ylabel('MSE')
            ax3.set_title('Mean Square Error (Lower = Better)')
            ax3.grid(True, alpha=0.3)

            for bar, value in zip(bars3, mse_values):
                height = bar.get_height()
                ax3.text(bar.get_x() + bar.get_width() / 2., height + 0.1,
                         f'{value:.3f}', ha='center', va='bottom')

            # Success rate comparison
            success_values = [trad['success_rate'] * 100, enh['success_rate'] * 100]
            bars4 = ax4.bar(methods, success_values, color=['plum', 'orchid'])
            ax4.set_ylabel('Success Rate (%)')
            ax4.set_title('Success Rate')
            ax4.set_ylim(0, 105)
            ax4.grid(True, alpha=0.3)

            for bar, value in zip(bars4, success_values):
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width() / 2., height + 1,
                         f'{value:.1f}%', ha='center', va='bottom')

            self.comparison_canvas.figure.tight_layout()
            self.comparison_canvas.draw()

        except Exception as e:
            print(f"Lỗi vẽ biểu đồ so sánh: {e}")

    def security_analysis(self):
        """Thực hiện phân tích bảo mật"""
        if self.stego_array is None or self.original_array is None:
            QMessageBox.warning(self, "Cảnh báo", "Vui lòng thực hiện embedding trước")
            return

        self.start_progress("Security analysis...")

        params = {
            'stego_array': self.stego_array,
            'original_array': self.original_array,
            'stego_path': self.stego_image_path,
            'key': self.current_key
        }

        self.worker = SteganographyWorker('security_test', params)
        self.worker.finished.connect(self.on_security_finished)
        self.worker.progress.connect(self.update_status)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_security_finished(self, result):
        """Xử lý kết quả security analysis"""
        self.stop_progress()

        if result['status'] == 'success':
            chi_square = result['chi_square']
            histogram = result['histogram']
            brute_force = result['brute_force']

            # Display results
            security_text = f"🔐 SECURITY ANALYSIS REPORT\n"
            security_text += f"{'=' * 50}\n\n"

            # Chi-square test
            security_text += f"📊 CHI-SQUARE TEST:\n"
            security_text += f"{'-' * 25}\n"
            security_text += f"Chi-square statistic: {chi_square['chi_square_statistic']:.4f}\n"
            security_text += f"Degrees of freedom: {chi_square['degrees_of_freedom']}\n"
            security_text += f"P-value: {chi_square['p_value']:.6f}\n"
            security_text += f"Suspicious: {'🚨 YES' if chi_square['suspicious'] else '✅ NO'}\n"
            security_text += f"Interpretation: {'Likely contains hidden data' if chi_square['suspicious'] else 'Appears normal'}\n\n"

            # Histogram analysis
            security_text += f"📈 HISTOGRAM ANALYSIS:\n"
            security_text += f"{'-' * 30}\n"
            security_text += f"Histogram correlation: {histogram['histogram_correlation']:.6f}\n"
            security_text += f"Histogram MSE: {histogram['histogram_mse']:.4f}\n"
            security_text += f"Max difference: {histogram['max_difference']}\n\n"

            # Brute force resistance
            security_text += f"🔨 BRUTE FORCE RESISTANCE:\n"
            security_text += f"{'-' * 35}\n"
            security_text += f"Total attempts: {brute_force['total_attempts']}\n"
            security_text += f"Successful extractions: {brute_force['successful_extractions']}\n"
            security_text += f"Valid extractions: {brute_force['valid_extractions']}\n"
            security_text += f"Resistance score: {brute_force['resistance_score']:.4f}\n"
            security_text += f"Security level: {brute_force['security_level']}\n\n"

            # Overall assessment
            security_text += f"🏆 OVERALL SECURITY ASSESSMENT:\n"
            security_text += f"{'-' * 40}\n"

            score = 0
            if not chi_square['suspicious']:
                score += 3
            if histogram['histogram_correlation'] > 0.9:
                score += 2
            if brute_force['security_level'] == 'HIGH':
                score += 3
            elif brute_force['security_level'] == 'MEDIUM':
                score += 1

            if score >= 7:
                assessment = "🔒 EXCELLENT - Very secure steganography"
            elif score >= 5:
                assessment = "✅ GOOD - Adequately secure"
            elif score >= 3:
                assessment = "⚠️ FAIR - Some security concerns"
            else:
                assessment = "🚨 POOR - Significant security risks"

            security_text += f"Security Score: {score}/8\n"
            security_text += f"Assessment: {assessment}\n"

            self.security_results_text.setText(security_text)

            # Plot security charts
            self.plot_security_charts(result)

            self.status_label.setText("✅ Security analysis hoàn thành!")

        else:
            QMessageBox.critical(self, "Lỗi", "Security analysis failed")

    def plot_security_charts(self, result):
        """Vẽ biểu đồ phân tích bảo mật"""
        try:
            self.security_canvas.figure.clear()

            # Create subplots
            ax1 = self.security_canvas.figure.add_subplot(221)
            ax2 = self.security_canvas.figure.add_subplot(222)
            ax3 = self.security_canvas.figure.add_subplot(223)
            ax4 = self.security_canvas.figure.add_subplot(224)

            chi_square = result['chi_square']
            histogram = result['histogram']
            brute_force = result['brute_force']

            # Chi-square test result
            suspicious = chi_square['suspicious']
            ax1.pie([1 if suspicious else 0, 0 if suspicious else 1],
                    labels=['Suspicious', 'Normal'],
                    colors=['red', 'green'],
                    autopct='',
                    startangle=90)
            ax1.set_title(f'Chi-square Test\nP-value: {chi_square["p_value"]:.6f}')

            # Histogram correlation
            corr = histogram['histogram_correlation']
            ax2.bar(['Correlation'], [corr], color='skyblue')
            ax2.set_ylim(0, 1)
            ax2.set_ylabel('Correlation')
            ax2.set_title(f'Histogram Correlation\n{corr:.6f}')
            ax2.grid(True, alpha=0.3)

            # Brute force resistance
            resistance = brute_force['resistance_score']
            colors = ['red' if resistance < 0.95 else 'orange' if resistance < 0.99 else 'green']
            ax3.bar(['Resistance'], [resistance], color=colors)
            ax3.set_ylim(0, 1)
            ax3.set_ylabel('Resistance Score')
            ax3.set_title(f'Brute Force Resistance\n{resistance:.4f} ({brute_force["security_level"]})')
            ax3.grid(True, alpha=0.3)

            # Security score radar (simplified)
            scores = [
                3 if not chi_square['suspicious'] else 0,  # Chi-square
                2 if histogram['histogram_correlation'] > 0.9 else 1 if histogram['histogram_correlation'] > 0.8 else 0,
                # Histogram
                3 if brute_force['security_level'] == 'HIGH' else 1 if brute_force['security_level'] == 'MEDIUM' else 0
                # Brute force
            ]

            categories = ['Chi-square\nResistance', 'Histogram\nPreservation', 'Brute Force\nResistance']
            ax4.bar(categories, scores, color=['lightcoral', 'lightblue', 'lightgreen'])
            ax4.set_ylim(0, 3.5)
            ax4.set_ylabel('Security Score')
            ax4.set_title(f'Security Components\nTotal: {sum(scores)}/8')
            ax4.tick_params(axis='x', rotation=45)

            self.security_canvas.figure.tight_layout()
            self.security_canvas.draw()

        except Exception as e:
            print(f"Lỗi vẽ biểu đồ bảo mật: {e}")

    def start_progress(self, message):
        """Bắt đầu progress bar"""
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_label.setText(f"⏳ {message}")

        # Disable buttons
        self.embed_btn.setEnabled(False)
        self.extract_btn.setEnabled(False)
        self.compare_btn.setEnabled(False)
        self.security_btn.setEnabled(False)

    def stop_progress(self):
        """Dừng progress bar"""
        self.progress_bar.setVisible(False)

        # Re-enable buttons
        self.embed_btn.setEnabled(True)
        if self.stego_array is not None:
            self.extract_btn.setEnabled(True)
            self.security_btn.setEnabled(True)
        self.compare_btn.setEnabled(True)

    def update_status(self, message):
        """Cập nhật status"""
        self.status_label.setText(f"⏳ {message}")

    def on_error(self, error_message):
        """Xử lý lỗi"""
        self.stop_progress()
        QMessageBox.critical(self, "Lỗi", error_message)
        self.status_label.setText(f"❌ Lỗi: {error_message}")

    def closeEvent(self, event):
        """Xử lý khi đóng ứng dụng"""
        # Cleanup temporary files
        try:
            if hasattr(self, 'stego_image_path') and os.path.exists(self.stego_image_path):
                os.remove(self.stego_image_path)

            # Remove test images
            test_files = ['gui_test_image.png']
            for file in test_files:
                if os.path.exists(file):
                    os.remove(file)
        except:
            pass

        event.accept()


# =============================== MAIN ===============================
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    # Set application style
    app.setStyle('Fusion')

    # Dark theme (optional)
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(53, 53, 53))
    palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(255, 255, 255))
    app.setPalette(palette)

    gui = SteganographyGUI()
    gui.show()

    sys.exit(app.exec_())