import sys
import os
import cv2
import numpy as np
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from PIL import Image
import hashlib
import random
import time
from scipy import stats
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import ( QSplitter, QFileDialog,
                             QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
                             QTabWidget)
from collections import Counter
import warnings

warnings.filterwarnings('ignore')


class EnhancedLSBSteganography:
    """Enhanced LSB Steganography with Random Pixel Selection and Secret Key"""

    def __init__(self, end_marker="###END###"):
        self.end_marker = end_marker
        self.prng_state = None

    def _process_key(self, key):
        """Convert string key to numeric seed"""
        if isinstance(key, str):
            hash_object = hashlib.md5(key.encode())
            hash_hex = hash_object.hexdigest()
            return int(hash_hex[:8], 16)
        return int(key) % (2 ** 32)

    def _initialize_prng(self, seed):
        """Initialize PRNG with given seed"""
        random.seed(seed)
        self.prng_state = random.getstate()

    def _string_to_bits(self, text):
        """Convert string to list of bits"""
        bits = []
        for char in text:
            byte_val = ord(char)
            for i in range(8):
                bits.append((byte_val >> (7 - i)) & 1)
        return bits

    def _bits_to_string(self, bits):
        """Convert list of bits to string"""
        chars = []
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte_bits = bits[i:i + 8]
                byte_val = 0
                for j, bit in enumerate(byte_bits):
                    byte_val |= (bit << (7 - j))
                try:
                    chars.append(chr(byte_val))
                except ValueError:
                    continue
        return ''.join(chars)

    def _generate_position_sequence(self, shape, seed):
        """Generate shuffled position sequence using Fisher-Yates"""
        height, width, channels = shape
        positions = []

        for i in range(height):
            for j in range(width):
                for k in range(channels):
                    positions.append((i, j, k))

        self._initialize_prng(seed)
        for i in range(len(positions) - 1, 0, -1):
            j = random.randint(0, i)
            positions[i], positions[j] = positions[j], positions[i]

        return positions

    def embed_message(self, image_array, message, secret_key):
        """Embed message in image using enhanced LSB"""
        try:
            if len(image_array.shape) == 2:
                # Convert grayscale to RGB
                image_array = np.stack([image_array] * 3, axis=-1)

            height, width, channels = image_array.shape
            message_with_delimiter = message + self.end_marker
            message_bits = self._string_to_bits(message_with_delimiter)

            max_capacity = height * width * channels
            if len(message_bits) > max_capacity:
                raise ValueError(f"Message too long")

            seed = self._process_key(secret_key)
            position_sequence = self._generate_position_sequence(image_array.shape, seed)

            stego_array = image_array.copy()

            for bit_index, bit in enumerate(message_bits):
                if bit_index >= len(position_sequence):
                    break
                pos_i, pos_j, pos_k = position_sequence[bit_index]
                pixel_value = stego_array[pos_i][pos_j][pos_k]
                new_pixel_value = (pixel_value & 0xFE) | bit
                stego_array[pos_i][pos_j][pos_k] = new_pixel_value

            return stego_array

        except Exception as e:
            print(f"Error during embedding: {str(e)}")
            return None

    def extract_message(self, stego_array, secret_key):
        """Extract message from stego image"""
        try:
            if len(stego_array.shape) == 2:
                stego_array = np.stack([stego_array] * 3, axis=-1)

            seed = self._process_key(secret_key)
            position_sequence = self._generate_position_sequence(stego_array.shape, seed)

            extracted_bits = []
            end_marker_bits = self._string_to_bits(self.end_marker)
            end_marker_length = len(end_marker_bits)

            for pos_i, pos_j, pos_k in position_sequence:
                lsb = stego_array[pos_i][pos_j][pos_k] & 1
                extracted_bits.append(lsb)

                if len(extracted_bits) >= end_marker_length and len(extracted_bits) % 8 == 0:
                    if extracted_bits[-end_marker_length:] == end_marker_bits:
                        break

                if len(extracted_bits) > len(position_sequence):
                    break

            if len(extracted_bits) >= end_marker_length:
                message_bits = extracted_bits[:-end_marker_length]
                extracted_message = self._bits_to_string(message_bits)
                return extracted_message
            else:
                return ""

        except Exception as e:
            print(f"Error during extraction: {str(e)}")
            return None

    def calculate_psnr(self, original, stego):
        """Calculate Peak Signal-to-Noise Ratio"""
        mse = np.mean((original.astype(float) - stego.astype(float)) ** 2)
        if mse == 0:
            return float('inf')
        max_pixel = 255.0
        psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
        return psnr

    def calculate_mse(self, original, stego):
        """Calculate Mean Square Error"""
        return np.mean((original.astype(float) - stego.astype(float)) ** 2)


class TraditionalLSB:
    """Traditional Sequential LSB for comparison"""

    def __init__(self, end_marker="###END###"):
        self.end_marker = end_marker

    def _string_to_bits(self, text):
        """Convert string to list of bits"""
        bits = []
        for char in text:
            byte_val = ord(char)
            for i in range(8):
                bits.append((byte_val >> (7 - i)) & 1)
        return bits

    def _bits_to_string(self, bits):
        """Convert list of bits to string"""
        chars = []
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte_bits = bits[i:i + 8]
                byte_val = 0
                for j, bit in enumerate(byte_bits):
                    byte_val |= (bit << (7 - j))
                try:
                    chars.append(chr(byte_val))
                except ValueError:
                    continue
        return ''.join(chars)

    def embed(self, image_array, message):
        """Traditional sequential LSB embedding"""
        if len(image_array.shape) == 2:
            image_array = np.stack([image_array] * 3, axis=-1)

        stego_array = image_array.copy()
        message_with_delimiter = message + self.end_marker
        message_bits = self._string_to_bits(message_with_delimiter)

        height, width, channels = image_array.shape
        bit_index = 0

        for i in range(height):
            for j in range(width):
                for k in range(channels):
                    if bit_index < len(message_bits):
                        pixel_value = stego_array[i][j][k]
                        new_pixel_value = (pixel_value & 0xFE) | message_bits[bit_index]
                        stego_array[i][j][k] = new_pixel_value
                        bit_index += 1
                    else:
                        return stego_array

        return stego_array

    def extract(self, stego_array):
        """Traditional sequential LSB extraction"""
        if len(stego_array.shape) == 2:
            stego_array = np.stack([stego_array] * 3, axis=-1)

        extracted_bits = []
        end_marker_bits = self._string_to_bits(self.end_marker)
        end_marker_length = len(end_marker_bits)

        height, width, channels = stego_array.shape

        for i in range(height):
            for j in range(width):
                for k in range(channels):
                    lsb = stego_array[i][j][k] & 1
                    extracted_bits.append(lsb)

                    if len(extracted_bits) >= end_marker_length and len(extracted_bits) % 8 == 0:
                        if extracted_bits[-end_marker_length:] == end_marker_bits:
                            message_bits = extracted_bits[:-end_marker_length]
                            return self._bits_to_string(message_bits)

        return ""

    def calculate_psnr(self, original, stego):
        """Calculate PSNR"""
        mse = np.mean((original.astype(float) - stego.astype(float)) ** 2)
        if mse == 0:
            return float('inf')
        return 20 * np.log10(255.0 / np.sqrt(mse))

    def calculate_mse(self, original, stego):
        """Calculate MSE"""
        return np.mean((original.astype(float) - stego.astype(float)) ** 2)


class SecurityTester:
    """Security testing and analysis tools"""

    def chi_square_test(self, image_array):
        """Perform Chi-square test for LSB embedding detection"""
        if len(image_array.shape) == 3:
            image_flat = image_array[:, :, 0].flatten()
        else:
            image_flat = image_array.flatten()

        histogram = np.histogram(image_flat, bins=256, range=(0, 256))[0]
        chi_square = 0
        pairs_tested = 0

        for i in range(0, 255, 2):
            expected = (histogram[i] + histogram[i + 1]) / 2.0
            if expected > 0:
                chi_square += ((histogram[i] - expected) ** 2) / expected
                chi_square += ((histogram[i + 1] - expected) ** 2) / expected
                pairs_tested += 1

        degrees_of_freedom = pairs_tested - 1
        if degrees_of_freedom > 0:
            p_value = 1 - stats.chi2.cdf(chi_square, degrees_of_freedom)
        else:
            p_value = 1.0

        return {
            'chi_square_statistic': chi_square,
            'degrees_of_freedom': degrees_of_freedom,
            'p_value': p_value,
            'suspicious': p_value < 0.05
        }

    def histogram_analysis(self, original_array, stego_array):
        """Compare histograms of original and stego images"""
        orig_hist = np.histogram(original_array.flatten(), bins=256, range=(0, 256))[0]
        stego_hist = np.histogram(stego_array.flatten(), bins=256, range=(0, 256))[0]

        correlation = np.corrcoef(orig_hist, stego_hist)[0, 1]
        mse_hist = np.mean((orig_hist - stego_hist) ** 2)

        return {
            'histogram_correlation': correlation,
            'histogram_mse': mse_hist,
            'max_difference': np.max(np.abs(orig_hist - stego_hist))
        }


class SteganographyGUI(QtWidgets.QMainWindow):
    """Comprehensive GUI for LSB Steganography Analysis"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enhanced LSB Steganography - Comprehensive Analysis Tool")
        self.resize(1800, 1200)

        # Initialize engines
        self.enhanced_lsb = EnhancedLSBSteganography()
        self.traditional_lsb = TraditionalLSB()
        self.security_tester = SecurityTester()

        # Data holders
        self.cover_image = None
        self.stego_images = {}  # {'enhanced': array, 'traditional': array}
        self.current_message = ""
        self.current_key = ""
        self.analysis_results = {}

        self.setup_ui()

    def setup_ui(self):
        """Setup the main UI"""
        central = QtWidgets.QWidget(self)
        self.setCentralWidget(central)
        main_layout = QtWidgets.QVBoxLayout(central)

        # === IMAGE LOADING SECTION ===
        image_group = QtWidgets.QGroupBox("1. Cover Image Selection")
        image_layout = QtWidgets.QHBoxLayout(image_group)

        self.image_path_line = QtWidgets.QLineEdit()
        self.image_path_line.setReadOnly(True)
        browse_btn = QtWidgets.QPushButton("Browse Image...")
        browse_btn.clicked.connect(self.browse_image)
        load_btn = QtWidgets.QPushButton("Load Image")
        load_btn.clicked.connect(self.load_image)

        # Image info display
        self.image_info = QtWidgets.QLabel("No image loaded")
        self.image_info.setMaximumHeight(40)

        image_layout.addWidget(QtWidgets.QLabel("Image Path:"))
        image_layout.addWidget(self.image_path_line)
        image_layout.addWidget(browse_btn)
        image_layout.addWidget(load_btn)
        image_layout.addWidget(self.image_info)

        main_layout.addWidget(image_group)

        # === MESSAGE INPUT SECTION ===
        message_group = QtWidgets.QGroupBox("2. Secret Message & Key Configuration")
        message_layout = QtWidgets.QVBoxLayout(message_group)

        # Message input
        msg_input_layout = QtWidgets.QHBoxLayout()
        self.message_text = QtWidgets.QTextEdit()
        self.message_text.setMaximumHeight(100)
        self.message_text.setPlaceholderText("Enter your secret message here...")

        # Key input
        key_layout = QtWidgets.QHBoxLayout()
        self.key_input = QtWidgets.QLineEdit()
        self.key_input.setPlaceholderText("Enter secret key for Enhanced LSB...")
        self.key_strength = QtWidgets.QLabel("Key Strength: -")

        self.key_input.textChanged.connect(self.update_key_strength)

        key_layout.addWidget(QtWidgets.QLabel("Secret Key:"))
        key_layout.addWidget(self.key_input)
        key_layout.addWidget(self.key_strength)

        # Message stats
        self.message_stats = QtWidgets.QLabel("Message: 0 characters, 0 bits")
        self.message_text.textChanged.connect(self.update_message_stats)

        message_layout.addWidget(QtWidgets.QLabel("Secret Message:"))
        message_layout.addWidget(self.message_text)
        message_layout.addLayout(key_layout)
        message_layout.addWidget(self.message_stats)

        main_layout.addWidget(message_group)

        # === OPERATIONS SECTION ===
        ops_group = QtWidgets.QGroupBox("3. Steganography Operations")
        ops_layout = QtWidgets.QVBoxLayout(ops_group)

        # Method selection
        method_layout = QtWidgets.QHBoxLayout()
        self.method_enhanced = QtWidgets.QCheckBox("Enhanced LSB (Random + Key)")
        self.method_traditional = QtWidgets.QCheckBox("Traditional LSB (Sequential)")
        self.method_enhanced.setChecked(True)
        self.method_traditional.setChecked(True)

        method_layout.addWidget(QtWidgets.QLabel("Methods to test:"))
        method_layout.addWidget(self.method_enhanced)
        method_layout.addWidget(self.method_traditional)
        method_layout.addStretch()

        # Operation buttons
        button_layout = QtWidgets.QHBoxLayout()
        embed_btn = QtWidgets.QPushButton("🔒 Embed Message")
        embed_btn.clicked.connect(self.embed_message)
        extract_btn = QtWidgets.QPushButton("🔓 Extract Message")
        extract_btn.clicked.connect(self.extract_message)
        analyze_btn = QtWidgets.QPushButton("🔍 Security Analysis")
        analyze_btn.clicked.connect(self.perform_security_analysis)
        compare_btn = QtWidgets.QPushButton("📊 Compare Methods")
        compare_btn.clicked.connect(self.compare_methods)

        button_layout.addWidget(embed_btn)
        button_layout.addWidget(extract_btn)
        button_layout.addWidget(analyze_btn)
        button_layout.addWidget(compare_btn)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)

        ops_layout.addLayout(method_layout)
        ops_layout.addLayout(button_layout)
        ops_layout.addWidget(self.progress_bar)

        main_layout.addWidget(ops_group)

        # === RESULTS SECTION ===
        results_splitter = QSplitter(QtCore.Qt.Horizontal)

        # Left panel - Text results and tables
        left_widget = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_widget)

        # Results summary
        self.results_summary = QtWidgets.QTextEdit()
        self.results_summary.setMaximumHeight(120)  # Giảm để chừa chỗ cho bảng
        self.results_summary.setReadOnly(True)
        left_layout.addWidget(QtWidgets.QLabel("Operation Results:"))
        left_layout.addWidget(self.results_summary)

        # === THÊM BẢNG SO SÁNH ===
        left_layout.addWidget(QtWidgets.QLabel("Method Comparison:"))
        self.comparison_table = QTableWidget()
        self.setup_comparison_table()
        left_layout.addWidget(self.comparison_table)

        # Security analysis
        self.security_results = QtWidgets.QTextEdit()
        self.security_results.setMaximumHeight(150)  # Giảm kích thước
        self.security_results.setReadOnly(True)
        left_layout.addWidget(QtWidgets.QLabel("Security Analysis:"))
        left_layout.addWidget(self.security_results)

        results_splitter.addWidget(left_widget)

        # Right panel - Visualizations
        right_widget = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_widget)

        self.viz_tabs = QTabWidget()

        # Tab 1: Image comparison
        self.image_canvas = PlotCanvas()
        self.viz_tabs.addTab(self.image_canvas, "Image Comparison")

        # Tab 2: Difference maps
        self.diff_canvas = PlotCanvas()
        self.viz_tabs.addTab(self.diff_canvas, "Difference Maps")

        # Tab 3: Histogram analysis
        self.histogram_canvas = PlotCanvas()
        self.viz_tabs.addTab(self.histogram_canvas, "Histogram Analysis")

        # Tab 4: Quality metrics
        self.metrics_canvas = PlotCanvas()
        self.viz_tabs.addTab(self.metrics_canvas, "Quality Metrics")

        # Tab 5: Security analysis
        self.security_canvas = PlotCanvas()
        self.viz_tabs.addTab(self.security_canvas, "Security Analysis")

        right_layout.addWidget(self.viz_tabs)
        results_splitter.addWidget(right_widget)

        main_layout.addWidget(results_splitter)

        # === BATCH PROCESSING SECTION ===
        batch_group = QtWidgets.QGroupBox("4. Batch Processing & Advanced Operations")
        batch_layout = QtWidgets.QHBoxLayout(batch_group)

        batch_btn = QtWidgets.QPushButton("📁 Batch Process Directory")
        batch_btn.clicked.connect(self.batch_process)

        export_btn = QtWidgets.QPushButton("💾 Export Results")
        export_btn.clicked.connect(self.export_results)

        clear_btn = QtWidgets.QPushButton("🗑️ Clear Results")
        clear_btn.clicked.connect(self.clear_results)

        batch_layout.addWidget(batch_btn)
        batch_layout.addWidget(export_btn)
        batch_layout.addWidget(clear_btn)
        batch_layout.addStretch()

        main_layout.addWidget(batch_group)

    def setup_comparison_table(self):
        """Setup method comparison table"""
        self.comparison_table.setRowCount(2)
        self.comparison_table.setColumnCount(7)  # Thêm cột cho difference pattern

        headers = ["Method", "PSNR (dB)", "MSE", "Embed Time", "Extract Time", "Security Score", "Difference Pattern"]
        self.comparison_table.setHorizontalHeaderLabels(headers)
        self.comparison_table.setVerticalHeaderLabels(["Enhanced LSB", "Traditional LSB"])

        self.comparison_table.setMaximumHeight(120)
        # Adjust column widths
        for i in range(6):
            if i < 5:
                self.comparison_table.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeToContents)
            else:
                self.comparison_table.horizontalHeader().setSectionResizeMode(i, QHeaderView.Stretch)

    def analyze_difference_pattern(self, method_name, stego_array):
        """Analyze difference pattern for table display"""
        if self.cover_image is None or stego_array is None:
            return "No data"

        # Calculate difference
        if len(self.cover_image.shape) == 3:
            cover_gray = cv2.cvtColor(self.cover_image, cv2.COLOR_RGB2GRAY)
        else:
            cover_gray = self.cover_image

        if len(stego_array.shape) == 3:
            stego_gray = cv2.cvtColor(stego_array, cv2.COLOR_RGB2GRAY)
        else:
            stego_gray = stego_array

        diff = cv2.absdiff(cover_gray, stego_gray)
        non_zero = np.count_nonzero(diff)
        total_pixels = diff.shape[0] * diff.shape[1]
        percentage = (non_zero / total_pixels) * 100

        if method_name.lower() == 'traditional':
            # Check if changes are concentrated in top-left (sequential pattern)
            h, w = diff.shape
            top_left_quarter = diff[:h//4, :w//4]
            top_left_changes = np.count_nonzero(top_left_quarter)
            if top_left_changes > non_zero * 0.6:  # More than 60% in top-left quarter
                pattern = f"Sequential ({percentage:.1f}%)"
            else:
                pattern = f"Scattered ({percentage:.1f}%)"
        else:  # Enhanced
            pattern = f"Random distribution ({percentage:.1f}%)"

        return pattern

    def browse_image(self):
        """Browse for cover image"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Cover Image", "",
            "Image Files (*.png *.jpg *.jpeg *.bmp *.tiff);;All Files (*)"
        )
        if file_path:
            self.image_path_line.setText(file_path)

    def load_image(self):
        """Load and analyze cover image"""
        image_path = self.image_path_line.text()
        if not image_path or not os.path.exists(image_path):
            QtWidgets.QMessageBox.warning(self, "Warning", "Please select a valid image file")
            return

        try:
            # Load image
            img_pil = Image.open(image_path)
            if img_pil.mode != 'RGB':
                img_pil = img_pil.convert('RGB')
            self.cover_image = np.array(img_pil)

            # Calculate capacity
            height, width, channels = self.cover_image.shape
            max_bits = height * width * channels
            max_chars = max_bits // 8 - len(self.enhanced_lsb.end_marker)

            # Update UI
            self.image_info.setText(
                f"Loaded: {width}x{height}x{channels}, Max capacity: {max_chars:,} characters"
            )

            # Display original image
            self.plot_original_image()

            QtWidgets.QMessageBox.information(
                self, "Success", f"Image loaded successfully!\nCapacity: {max_chars:,} characters"
            )

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Error loading image: {str(e)}")

    def plot_original_image(self):
        """Plot original cover image"""
        if self.cover_image is None:
            return

        self.image_canvas.figure.clear()
        ax = self.image_canvas.figure.add_subplot(111)
        ax.imshow(self.cover_image)
        ax.set_title("Cover Image")
        ax.axis('off')
        self.image_canvas.figure.tight_layout()
        self.image_canvas.draw()

    def update_message_stats(self):
        """Update message statistics"""
        message = self.message_text.toPlainText()
        char_count = len(message)
        bit_count = char_count * 8 + len(self.enhanced_lsb.end_marker) * 8

        self.message_stats.setText(f"Message: {char_count} characters, {bit_count} bits")

        # Check capacity
        if self.cover_image is not None:
            height, width, channels = self.cover_image.shape
            max_capacity = height * width * channels
            utilization = (bit_count / max_capacity) * 100 if max_capacity > 0 else 0

            if utilization > 100:
                self.message_stats.setStyleSheet("color: red")
                self.message_stats.setText(self.message_stats.text() + f" - ⚠️ EXCEEDS CAPACITY ({utilization:.1f}%)")
            elif utilization > 80:
                self.message_stats.setStyleSheet("color: orange")
                self.message_stats.setText(self.message_stats.text() + f" - High usage ({utilization:.1f}%)")
            else:
                self.message_stats.setStyleSheet("color: green")
                self.message_stats.setText(self.message_stats.text() + f" - OK ({utilization:.1f}%)")

    def update_key_strength(self):
        """Update key strength indicator"""
        key = self.key_input.text()
        if len(key) == 0:
            self.key_strength.setText("Key Strength: -")
            self.key_strength.setStyleSheet("color: gray")
        elif len(key) < 6:
            self.key_strength.setText("Key Strength: Weak")
            self.key_strength.setStyleSheet("color: red")
        elif len(key) < 12:
            self.key_strength.setText("Key Strength: Medium")
            self.key_strength.setStyleSheet("color: orange")
        else:
            self.key_strength.setText("Key Strength: Strong")
            self.key_strength.setStyleSheet("color: green")

    def embed_message(self):
        """Embed message using selected methods"""
        if self.cover_image is None:
            QtWidgets.QMessageBox.warning(self, "Warning", "Please load a cover image first")
            return

        message = self.message_text.toPlainText().strip()
        if not message:
            QtWidgets.QMessageBox.warning(self, "Warning", "Please enter a message to embed")
            return

        key = self.key_input.text().strip()
        if self.method_enhanced.isChecked() and not key:
            QtWidgets.QMessageBox.warning(self, "Warning", "Please enter a secret key for Enhanced LSB")
            return

        try:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress

            self.current_message = message
            self.current_key = key
            results_text = ""

            # Enhanced LSB
            if self.method_enhanced.isChecked():
                start_time = time.time()
                stego_enhanced = self.enhanced_lsb.embed_message(self.cover_image, message, key)
                embed_time_enhanced = time.time() - start_time

                if stego_enhanced is not None:
                    self.stego_images['enhanced'] = stego_enhanced
                    psnr_enhanced = self.enhanced_lsb.calculate_psnr(self.cover_image, stego_enhanced)
                    mse_enhanced = self.enhanced_lsb.calculate_mse(self.cover_image, stego_enhanced)

                    results_text += f"✅ Enhanced LSB: Embedded in {embed_time_enhanced:.3f}s\n"
                    results_text += f"   PSNR: {psnr_enhanced:.2f} dB, MSE: {mse_enhanced:.4f}\n\n"
                else:
                    results_text += "❌ Enhanced LSB: Embedding failed\n\n"

            # Traditional LSB
            if self.method_traditional.isChecked():
                start_time = time.time()
                stego_traditional = self.traditional_lsb.embed(self.cover_image, message)
                embed_time_traditional = time.time() - start_time

                if stego_traditional is not None:
                    self.stego_images['traditional'] = stego_traditional
                    psnr_traditional = self.traditional_lsb.calculate_psnr(self.cover_image, stego_traditional)
                    mse_traditional = self.traditional_lsb.calculate_mse(self.cover_image, stego_traditional)

                    results_text += f"✅ Traditional LSB: Embedded in {embed_time_traditional:.3f}s\n"
                    results_text += f"   PSNR: {psnr_traditional:.2f} dB, MSE: {mse_traditional:.4f}\n\n"
                else:
                    results_text += "❌ Traditional LSB: Embedding failed\n\n"

            self.results_summary.setText(results_text)
            self.plot_image_comparison()
            self.plot_difference_maps()  # Vẽ bản đồ sai khác
            self.progress_bar.setVisible(False)

            QtWidgets.QMessageBox.information(self, "Success", "Message embedding completed!")

        except Exception as e:
            self.progress_bar.setVisible(False)
            QtWidgets.QMessageBox.critical(self, "Error", f"Embedding error: {str(e)}")

    def plot_difference_maps(self):
        """Plot difference maps between original and stego images"""
        if not self.stego_images:
            return

        self.diff_canvas.figure.clear()

        # Convert cover image to grayscale if needed
        if len(self.cover_image.shape) == 3:
            cover_gray = cv2.cvtColor(self.cover_image, cv2.COLOR_RGB2GRAY)
        else:
            cover_gray = self.cover_image

        num_plots = 1 + len(self.stego_images)  # Original + difference maps

        # Plot original image
        ax1 = self.diff_canvas.figure.add_subplot(1, num_plots, 1)
        ax1.imshow(cover_gray, cmap='gray')
        ax1.set_title("Original Cover")
        ax1.axis('off')

        # Plot difference maps
        plot_idx = 2
        for method, stego_array in self.stego_images.items():
            # Convert stego to grayscale if needed
            if len(stego_array.shape) == 3:
                stego_gray = cv2.cvtColor(stego_array, cv2.COLOR_RGB2GRAY)
            else:
                stego_gray = stego_array

            # Calculate difference (amplified for visibility)
            diff = cv2.absdiff(cover_gray, stego_gray)
            diff_amplified = np.clip(diff.astype(float) * 50, 0, 255).astype(np.uint8)

            ax = self.diff_canvas.figure.add_subplot(1, num_plots, plot_idx)
            im = ax.imshow(diff_amplified, cmap='hot', vmin=0, vmax=255)
            ax.set_title(f"Difference Map\n({method.title()} LSB)")
            ax.axis('off')

            # Add colorbar for the last plot
            if plot_idx == num_plots:
                cbar = self.diff_canvas.figure.colorbar(im, ax=ax, shrink=0.6)
                cbar.set_label('Difference (amplified)', rotation=270, labelpad=15)

            plot_idx += 1

        self.diff_canvas.figure.tight_layout()
        self.diff_canvas.draw()

    def extract_message(self):
        """Extract messages from stego images"""
        if not self.stego_images:
            QtWidgets.QMessageBox.warning(self, "Warning", "Please embed a message first")
            return

        try:
            results_text = "=== MESSAGE EXTRACTION RESULTS ===\n\n"
            results_text += f"Original Message: '{self.current_message}'\n\n"

            # Extract from Enhanced LSB
            if 'enhanced' in self.stego_images:
                start_time = time.time()
                extracted_enhanced = self.enhanced_lsb.extract_message(
                    self.stego_images['enhanced'], self.current_key
                )
                extract_time_enhanced = time.time() - start_time

                results_text += f"Enhanced LSB Extraction ({extract_time_enhanced:.3f}s):\n"
                results_text += f"  Extracted: '{extracted_enhanced}'\n"
                if extracted_enhanced == self.current_message:
                    results_text += "  Status: ✅ SUCCESS - Perfect match!\n\n"
                else:
                    results_text += "  Status: ❌ FAILED - Message corrupted or wrong key\n\n"

            # Extract from Traditional LSB
            if 'traditional' in self.stego_images:
                start_time = time.time()
                extracted_traditional = self.traditional_lsb.extract(self.stego_images['traditional'])
                extract_time_traditional = time.time() - start_time

                results_text += f"Traditional LSB Extraction ({extract_time_traditional:.3f}s):\n"
                results_text += f"  Extracted: '{extracted_traditional}'\n"
                if extracted_traditional == self.current_message:
                    results_text += "  Status: ✅ SUCCESS - Perfect match!\n\n"
                else:
                    results_text += "  Status: ❌ FAILED - Message corrupted\n\n"

            self.results_summary.setText(results_text)

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Extraction error: {str(e)}")

    def perform_security_analysis(self):
        """Perform comprehensive security analysis"""
        if not self.stego_images:
            QtWidgets.QMessageBox.warning(self, "Warning", "Please embed a message first")
            return

        try:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)

            security_text = "=== SECURITY ANALYSIS RESULTS ===\n\n"

            for method, stego_array in self.stego_images.items():
                security_text += f"{method.upper()} LSB ANALYSIS:\n"
                security_text += "-" * 30 + "\n"

                # Chi-square test
                chi_result = self.security_tester.chi_square_test(stego_array)
                security_text += f"Chi-square Test:\n"
                security_text += f"  Statistic: {chi_result['chi_square_statistic']:.4f}\n"
                security_text += f"  P-value: {chi_result['p_value']:.6f}\n"
                security_text += f"  Suspicious: {'YES' if chi_result['suspicious'] else 'NO'}\n\n"

                # Histogram analysis
                hist_result = self.security_tester.histogram_analysis(self.cover_image, stego_array)
                security_text += f"Histogram Analysis:\n"
                security_text += f"  Correlation: {hist_result['histogram_correlation']:.6f}\n"
                security_text += f"  MSE: {hist_result['histogram_mse']:.2f}\n"
                security_text += f"  Max Difference: {hist_result['max_difference']}\n\n"

                # Overall security assessment
                if chi_result['suspicious']:
                    security_level = "🔴 HIGH RISK - Easily detectable"
                elif chi_result['p_value'] < 0.1:
                    security_level = "🟡 MEDIUM RISK - May be detectable"
                else:
                    security_level = "🟢 LOW RISK - Hard to detect"

                security_text += f"Security Assessment: {security_level}\n\n"

            self.security_results.setText(security_text)
            self.plot_histogram_analysis()
            self.plot_security_analysis()
            self.progress_bar.setVisible(False)

        except Exception as e:
            self.progress_bar.setVisible(False)
            QtWidgets.QMessageBox.critical(self, "Error", f"Security analysis error: {str(e)}")

    def compare_methods(self):
        """Compare different steganography methods"""
        if len(self.stego_images) < 2:
            QtWidgets.QMessageBox.warning(
                self, "Warning", "Please embed message with both methods for comparison"
            )
            return

        try:
            # Calculate metrics for comparison
            comparison_data = {}

            for method, stego_array in self.stego_images.items():
                if method == 'enhanced':
                    engine = self.enhanced_lsb
                else:
                    engine = self.traditional_lsb

                psnr = engine.calculate_psnr(self.cover_image, stego_array)
                mse = engine.calculate_mse(self.cover_image, stego_array)

                # Security score (based on chi-square p-value)
                chi_result = self.security_tester.chi_square_test(stego_array)
                security_score = min(1.0, chi_result['p_value'] * 20)  # Normalize to 0-1

                # Analyze difference pattern
                diff_pattern = self.analyze_difference_pattern(method, stego_array)

                comparison_data[method] = {
                    'psnr': psnr,
                    'mse': mse,
                    'security_score': security_score,
                    'embed_time': 0.0,  # Will be updated in real implementation
                    'extract_time': 0.0,
                    'diff_pattern': diff_pattern
                }

            # Update comparison table
            self.update_comparison_table(comparison_data)

            # Plot metrics comparison
            self.plot_metrics_comparison(comparison_data)

            QtWidgets.QMessageBox.information(self, "Success", "Method comparison completed!")

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Comparison error: {str(e)}")

    def update_comparison_table(self, data):
        """Update the comparison table with metrics"""
        methods = ['enhanced', 'traditional']
        display_names = ['Enhanced LSB', 'Traditional LSB']

        for row, (method, display_name) in enumerate(zip(methods, display_names)):
            if method in data:
                d = data[method]
                items = [
                    display_name,
                    f"{d['psnr']:.2f}",
                    f"{d['mse']:.4f}",
                    f"{d['embed_time']:.3f}s",
                    f"{d['extract_time']:.3f}s",
                    f"{d['security_score']:.3f}",
                    d['diff_pattern']
                ]

                for col, item_text in enumerate(items):
                    table_item = QTableWidgetItem(str(item_text))

                    # Format method name column
                    if col == 0:
                        table_item.setBackground(QtGui.QColor(240, 248, 255))
                        font = table_item.font()
                        font.setBold(True)
                        table_item.setFont(font)

                    # Highlight better values
                    elif col > 0 and col < 6:  # Skip method name and pattern description
                        if method == 'enhanced':
                            # Highlight if enhanced is better
                            other_method_data = data.get('traditional', {})
                            if ((col == 1 and d['psnr'] > other_method_data.get('psnr', 0)) or
                                    (col == 5 and d['security_score'] > other_method_data.get('security_score', 0))):
                                table_item.setBackground(QtGui.QColor(144, 238, 144))

                    self.comparison_table.setItem(row, col, table_item)

        # Adjust row heights to fit content
        self.comparison_table.resizeRowsToContents()

    def plot_image_comparison(self):
        """Plot original vs stego images"""
        if not self.stego_images:
            return

        self.image_canvas.figure.clear()

        num_images = 1 + len(self.stego_images)  # original + stego images

        # Original image
        ax1 = self.image_canvas.figure.add_subplot(1, num_images, 1)
        ax1.imshow(self.cover_image)
        ax1.set_title("Original Cover")
        ax1.axis('off')

        # Stego images
        for i, (method, stego_array) in enumerate(self.stego_images.items(), 2):
            ax = self.image_canvas.figure.add_subplot(1, num_images, i)
            ax.imshow(stego_array)
            ax.set_title(f"Stego ({method.title()})")
            ax.axis('off')

        self.image_canvas.figure.tight_layout()
        self.image_canvas.draw()

    def plot_histogram_analysis(self):
        """Plot histogram comparison"""
        if not self.stego_images:
            return

        self.histogram_canvas.figure.clear()

        # Calculate histograms
        orig_hist = np.histogram(self.cover_image.flatten(), bins=256, range=(0, 256))[0]

        num_methods = len(self.stego_images)

        for i, (method, stego_array) in enumerate(self.stego_images.items(), 1):
            ax = self.histogram_canvas.figure.add_subplot(1, num_methods, i)

            stego_hist = np.histogram(stego_array.flatten(), bins=256, range=(0, 256))[0]

            x = np.arange(256)
            ax.plot(x, orig_hist, 'b-', alpha=0.7, label='Original', linewidth=1)
            ax.plot(x, stego_hist, 'r-', alpha=0.7, label='Stego', linewidth=1)

            ax.set_title(f'Histogram - {method.title()}')
            ax.set_xlabel('Pixel Value')
            ax.set_ylabel('Frequency')
            ax.legend()
            ax.grid(True, alpha=0.3)

        self.histogram_canvas.figure.tight_layout()
        self.histogram_canvas.draw()

    def plot_metrics_comparison(self, data):
        """Plot metrics comparison chart"""
        self.metrics_canvas.figure.clear()

        methods = list(data.keys())
        metrics = ['psnr', 'security_score']
        metric_names = ['PSNR (dB)', 'Security Score']

        ax1 = self.metrics_canvas.figure.add_subplot(121)
        psnr_values = [data[method]['psnr'] for method in methods]
        bars1 = ax1.bar([m.title() for m in methods], psnr_values,
                        color=['skyblue', 'lightcoral'])
        ax1.set_ylabel('PSNR (dB)')
        ax1.set_title('PSNR Comparison')
        ax1.grid(True, alpha=0.3)

        # Add value labels
        for bar, value in zip(bars1, psnr_values):
            ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                     f'{value:.1f}', ha='center', va='bottom')

        ax2 = self.metrics_canvas.figure.add_subplot(122)
        security_values = [data[method]['security_score'] for method in methods]
        bars2 = ax2.bar([m.title() for m in methods], security_values,
                        color=['lightgreen', 'orange'])
        ax2.set_ylabel('Security Score')
        ax2.set_title('Security Score Comparison')
        ax2.grid(True, alpha=0.3)

        # Add value labels
        for bar, value in zip(bars2, security_values):
            ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                     f'{value:.3f}', ha='center', va='bottom')

        self.metrics_canvas.figure.tight_layout()
        self.metrics_canvas.draw()

    def plot_security_analysis(self):
        """Plot security analysis visualization"""
        if not self.stego_images:
            return

        self.security_canvas.figure.clear()

        # Chi-square test results
        methods = []
        chi_values = []
        p_values = []

        for method, stego_array in self.stego_images.items():
            chi_result = self.security_tester.chi_square_test(stego_array)
            methods.append(method.title())
            chi_values.append(chi_result['chi_square_statistic'])
            p_values.append(chi_result['p_value'])

        # Plot chi-square statistics
        ax1 = self.security_canvas.figure.add_subplot(121)
        bars1 = ax1.bar(methods, chi_values, color=['blue', 'red'])
        ax1.set_ylabel('Chi-square Statistic')
        ax1.set_title('Chi-square Test Results')
        ax1.grid(True, alpha=0.3)

        # Plot p-values
        ax2 = self.security_canvas.figure.add_subplot(122)
        bars2 = ax2.bar(methods, p_values, color=['green', 'orange'])
        ax2.axhline(y=0.05, color='red', linestyle='--', label='Suspicion Threshold')
        ax2.set_ylabel('P-value')
        ax2.set_title('Statistical Significance')
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        self.security_canvas.figure.tight_layout()
        self.security_canvas.draw()

    def batch_process(self):
        """Batch process multiple images"""
        QtWidgets.QMessageBox.information(
            self, "Batch Processing",
            "Batch processing feature would process multiple images.\n"
            "This is a placeholder for the full implementation."
        )

    def export_results(self):
        """Export analysis results"""
        if not self.stego_images:
            QtWidgets.QMessageBox.warning(self, "Warning", "No results to export")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "steganography_results.txt",
            "Text Files (*.txt);;All Files (*)"
        )

        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write("=== STEGANOGRAPHY ANALYSIS RESULTS ===\n\n")
                    f.write(f"Message: {self.current_message}\n")
                    f.write(f"Key: {self.current_key}\n\n")
                    f.write(self.results_summary.toPlainText())
                    f.write("\n\n")
                    f.write(self.security_results.toPlainText())

                QtWidgets.QMessageBox.information(self, "Success", f"Results exported to {file_path}")

            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Error", f"Export error: {str(e)}")

    def clear_results(self):
        """Clear all results and reset UI"""
        self.stego_images.clear()
        self.analysis_results.clear()
        self.current_message = ""
        self.current_key = ""

        # Clear UI elements
        self.results_summary.clear()
        self.security_results.clear()

        # Clear visualizations
        for canvas in [self.image_canvas, self.diff_canvas, self.histogram_canvas,
                       self.metrics_canvas, self.security_canvas]:
            canvas.figure.clear()
            canvas.draw()

        # Clear comparison table
        for row in range(self.comparison_table.rowCount()):
            for col in range(self.comparison_table.columnCount()):
                self.comparison_table.setItem(row, col, QTableWidgetItem(""))

        QtWidgets.QMessageBox.information(self, "Success", "Results cleared")


class PlotCanvas(FigureCanvas):
    """Canvas for matplotlib plots"""

    def __init__(self, parent=None, width=12, height=8, dpi=100):
        self.figure = Figure(figsize=(width, height), dpi=dpi)
        super().__init__(self.figure)
        self.setParent(parent)


# =============================== MAIN ===============================
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    gui = SteganographyGUI()
    gui.show()
    sys.exit(app.exec_())