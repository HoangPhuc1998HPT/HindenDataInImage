import numpy as np
from PIL import Image
import hashlib
import random
import struct
import time
import os
import string
import matplotlib.pyplot as plt
from scipy import stats
import json


class EnhancedLSBSteganography:
    """
    Enhanced LSB Steganography with Random Pixel Selection and Secret Key
    """

    def __init__(self, end_marker="###END###"):
        self.end_marker = end_marker
        self.prng_state = None

    def _process_key(self, key):
        """Convert string key to numeric seed"""
        if isinstance(key, str):
            # Create hash-based seed
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
                    # Skip invalid characters
                    continue
        return ''.join(chars)

    def _generate_position_sequence(self, shape, seed):
        """Generate shuffled position sequence using Fisher-Yates"""
        height, width, channels = shape
        positions = []

        # Generate all possible positions
        for i in range(height):
            for j in range(width):
                for k in range(channels):
                    positions.append((i, j, k))

        # Shuffle using Fisher-Yates with PRNG
        self._initialize_prng(seed)
        for i in range(len(positions) - 1, 0, -1):
            j = random.randint(0, i)
            positions[i], positions[j] = positions[j], positions[i]

        return positions

    def embed_message(self, image_path, message, secret_key, output_path=None):
        """
        Embed message in image using enhanced LSB

        Args:
            image_path: Path to cover image
            message: Secret message to embed
            secret_key: Secret key for PRNG
            output_path: Path for stego image (optional)

        Returns:
            numpy array of stego image
        """
        try:
            # Load image
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            img_array = np.array(img)

            height, width, channels = img_array.shape

            # Prepare message with delimiter
            message_with_delimiter = message + self.end_marker
            message_bits = self._string_to_bits(message_with_delimiter)

            # Check capacity
            max_capacity = height * width * channels
            if len(message_bits) > max_capacity:
                raise ValueError(f"Message too long. Max capacity: {max_capacity} bits, "
                                 f"Message length: {len(message_bits)} bits")

            # Generate random position sequence
            seed = self._process_key(secret_key)
            position_sequence = self._generate_position_sequence(img_array.shape, seed)

            # Create stego image
            stego_array = img_array.copy()

            # Embed message bits
            for bit_index, bit in enumerate(message_bits):
                if bit_index >= len(position_sequence):
                    break

                pos_i, pos_j, pos_k = position_sequence[bit_index]
                pixel_value = stego_array[pos_i][pos_j][pos_k]

                # LSB substitution
                new_pixel_value = (pixel_value & 0xFE) | bit
                stego_array[pos_i][pos_j][pos_k] = new_pixel_value

            # Save stego image if path provided
            if output_path:
                stego_img = Image.fromarray(stego_array.astype(np.uint8))
                stego_img.save(output_path)
                print(f"Stego image saved to: {output_path}")

            return stego_array

        except Exception as e:
            print(f"Error during embedding: {str(e)}")
            return None

    def extract_message(self, stego_image_path, secret_key):
        """
        Extract message from stego image

        Args:
            stego_image_path: Path to stego image
            secret_key: Secret key used during embedding

        Returns:
            Extracted message string
        """
        try:
            # Load stego image
            img = Image.open(stego_image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            img_array = np.array(img)

            # Generate same position sequence
            seed = self._process_key(secret_key)
            position_sequence = self._generate_position_sequence(img_array.shape, seed)

            # Extract bits
            extracted_bits = []
            end_marker_bits = self._string_to_bits(self.end_marker)
            end_marker_length = len(end_marker_bits)

            for pos_i, pos_j, pos_k in position_sequence:
                # Extract LSB
                lsb = img_array[pos_i][pos_j][pos_k] & 1
                extracted_bits.append(lsb)

                # Check for end marker every 8 bits
                if len(extracted_bits) >= end_marker_length and len(extracted_bits) % 8 == 0:
                    # Check if we found the end marker
                    if extracted_bits[-end_marker_length:] == end_marker_bits:
                        break

                # Safety limit to prevent infinite extraction
                if len(extracted_bits) > len(position_sequence):
                    break

            # Remove end marker
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

    def get_embedding_capacity(self, image_path):
        """Calculate maximum embedding capacity"""
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        img_array = np.array(img)

        height, width, channels = img_array.shape

        max_bits = height * width * channels
        max_chars = max_bits // 8
        overhead = len(self.end_marker)

        return {
            'max_bits': max_bits,
            'max_characters': max_chars - overhead,
            'overhead_characters': overhead,
            'image_dimensions': (height, width, channels)
        }


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

    def extract(self, stego_array, message_length_hint=None):
        """Traditional sequential LSB extraction"""
        extracted_bits = []
        end_marker_bits = self._string_to_bits(self.end_marker)
        end_marker_length = len(end_marker_bits)

        height, width, channels = stego_array.shape

        for i in range(height):
            for j in range(width):
                for k in range(channels):
                    lsb = stego_array[i][j][k] & 1
                    extracted_bits.append(lsb)

                    # Check for end marker
                    if len(extracted_bits) >= end_marker_length and len(extracted_bits) % 8 == 0:
                        if extracted_bits[-end_marker_length:] == end_marker_bits:
                            message_bits = extracted_bits[:-end_marker_length]
                            return self._bits_to_string(message_bits)

        return ""


class SecurityTester:
    """Security testing and analysis tools"""

    def __init__(self, steganography_engine):
        self.engine = steganography_engine

    def chi_square_test(self, image_array):
        """Perform Chi-square test for LSB embedding detection"""
        if len(image_array.shape) == 3:
            # Use first channel for analysis
            image_flat = image_array[:, :, 0].flatten()
        else:
            image_flat = image_array.flatten()

        # Calculate histogram
        histogram = np.histogram(image_flat, bins=256, range=(0, 256))[0]

        # Chi-square calculation for pairs
        chi_square = 0
        pairs_tested = 0

        for i in range(0, 255, 2):
            expected = (histogram[i] + histogram[i + 1]) / 2.0
            if expected > 0:
                chi_square += ((histogram[i] - expected) ** 2) / expected
                chi_square += ((histogram[i + 1] - expected) ** 2) / expected
                pairs_tested += 1

        # Calculate p-value using chi-square distribution
        degrees_of_freedom = pairs_tested - 1
        if degrees_of_freedom > 0:
            p_value = 1 - stats.chi2.cdf(chi_square, degrees_of_freedom)
        else:
            p_value = 1.0

        return {
            'chi_square_statistic': chi_square,
            'degrees_of_freedom': degrees_of_freedom,
            'p_value': p_value,
            'suspicious': p_value < 0.05  # Threshold for suspicion
        }

    def histogram_analysis(self, original_array, stego_array):
        """Compare histograms of original and stego images"""
        orig_hist = np.histogram(original_array.flatten(), bins=256, range=(0, 256))[0]
        stego_hist = np.histogram(stego_array.flatten(), bins=256, range=(0, 256))[0]

        # Calculate similarity metrics
        correlation = np.corrcoef(orig_hist, stego_hist)[0, 1]
        mse_hist = np.mean((orig_hist - stego_hist) ** 2)

        return {
            'histogram_correlation': correlation,
            'histogram_mse': mse_hist,
            'max_difference': np.max(np.abs(orig_hist - stego_hist))
        }

    def brute_force_resistance_test(self, stego_image_path, correct_key, max_attempts=1000):
        """Test resistance to brute force attacks"""
        successful_extractions = 0
        valid_extractions = 0

        for attempt in range(max_attempts):
            # Generate random key
            fake_key = ''.join(random.choices(string.ascii_letters + string.digits, k=len(correct_key)))

            if fake_key == correct_key:
                continue  # Skip correct key

            try:
                extracted = self.engine.extract_message(stego_image_path, fake_key)
                if extracted is not None and len(extracted) > 0:
                    successful_extractions += 1
                    # Check if extraction seems valid (not complete gibberish)
                    if self._is_valid_text(extracted):
                        valid_extractions += 1
            except:
                continue

        resistance_score = 1 - (valid_extractions / max_attempts)

        return {
            'total_attempts': max_attempts,
            'successful_extractions': successful_extractions,
            'valid_extractions': valid_extractions,
            'resistance_score': resistance_score,
            'security_level': 'HIGH' if resistance_score > 0.99 else 'MEDIUM' if resistance_score > 0.95 else 'LOW'
        }

    def _is_valid_text(self, text):
        """Simple check if text seems like valid message"""
        try:
            if len(text) == 0:
                return False
            # Check if mostly printable ASCII
            printable_ratio = sum(1 for c in text if c.isprintable()) / len(text)
            return printable_ratio > 0.8
        except:
            return False


class SteganographyTester:
    """Comprehensive testing suite"""

    def __init__(self, steganography_engine):
        self.engine = steganography_engine

    def run_comprehensive_test(self, test_image_path, test_messages, test_keys):
        """Run comprehensive testing suite"""
        results = []

        for message in test_messages:
            for key in test_keys:
                result = self._single_test(test_image_path, message, key)
                results.append(result)

        return self._generate_report(results)

    def _single_test(self, image_path, message, key):
        """Perform single embedding/extraction test"""
        try:
            # Load original image
            original_img = np.array(Image.open(image_path))

            # Embed message
            stego_array = self.engine.embed_message(image_path, message, key)

            if stego_array is None:
                return {
                    'status': 'FAILED',
                    'error': 'Embedding failed',
                    'message_length': len(message),
                    'key': key
                }

            # Extract message
            # Save temporary stego image for extraction
            temp_path = f"temp_stego_{random.randint(1000, 9999)}.png"
            Image.fromarray(stego_array.astype(np.uint8)).save(temp_path)
            extracted_message = self.engine.extract_message(temp_path, key)

            # Clean up temporary file
            try:
                os.remove(temp_path)
            except:
                pass

            # Calculate metrics
            psnr = self.engine.calculate_psnr(original_img, stego_array)
            mse = self.engine.calculate_mse(original_img, stego_array)

            # Verify correctness
            is_correct = (extracted_message == message)

            return {
                'status': 'SUCCESS' if is_correct else 'FAILED',
                'message_original': message,
                'message_extracted': extracted_message,
                'message_length': len(message),
                'key': key,
                'psnr': psnr,
                'mse': mse,
                'correct_extraction': is_correct
            }

        except Exception as e:
            return {
                'status': 'ERROR',
                'error': str(e),
                'message_length': len(message),
                'key': key
            }

    def _generate_report(self, results):
        """Generate comprehensive test report"""
        total_tests = len(results)
        successful_tests = sum(1 for r in results if r['status'] == 'SUCCESS')

        psnr_values = [r['psnr'] for r in results if r['status'] == 'SUCCESS' and 'psnr' in r]
        mse_values = [r['mse'] for r in results if r['status'] == 'SUCCESS' and 'mse' in r]

        report = {
            'summary': {
                'total_tests': total_tests,
                'successful_tests': successful_tests,
                'success_rate': (successful_tests / total_tests * 100) if total_tests > 0 else 0,
                'failed_tests': total_tests - successful_tests
            },
            'quality_metrics': {
                'avg_psnr': np.mean(psnr_values) if psnr_values else 0,
                'min_psnr': np.min(psnr_values) if psnr_values else 0,
                'max_psnr': np.max(psnr_values) if psnr_values else 0,
                'avg_mse': np.mean(mse_values) if mse_values else 0,
                'std_psnr': np.std(psnr_values) if psnr_values else 0
            },
            'detailed_results': results
        }

        return report


class ComparativeAnalysis:
    """Comparative analysis between traditional and enhanced LSB"""

    def __init__(self):
        self.traditional_lsb = TraditionalLSB()
        self.enhanced_lsb = EnhancedLSBSteganography()

    def comprehensive_comparison(self, test_images, test_messages, test_key="default_key"):
        """Perform comprehensive comparison between methods"""
        results = {
            'traditional': [],
            'enhanced': []
        }

        for image_path in test_images:
            for message in test_messages:
                # Test traditional LSB
                trad_result = self._test_traditional(image_path, message)
                results['traditional'].append(trad_result)

                # Test enhanced LSB
                enh_result = self._test_enhanced(image_path, message, test_key)
                results['enhanced'].append(enh_result)

        return self._analyze_results(results)

    def _test_traditional(self, image_path, message):
        """Test traditional LSB method"""
        try:
            original_img = np.array(Image.open(image_path))
            if original_img.shape[2] != 3:
                # Convert to RGB if needed
                img_pil = Image.open(image_path).convert('RGB')
                original_img = np.array(img_pil)

            start_time = time.time()
            stego_array = self.traditional_lsb.embed(original_img, message)
            embed_time = time.time() - start_time

            start_time = time.time()
            extracted = self.traditional_lsb.extract(stego_array)
            extract_time = time.time() - start_time

            psnr = self._calculate_psnr(original_img, stego_array)
            mse = self._calculate_mse(original_img, stego_array)

            # Security tests
            security_tester = SecurityTester(self.enhanced_lsb)
            chi_square_result = security_tester.chi_square_test(stego_array)

            return {
                'method': 'traditional',
                'image': image_path,
                'message_length': len(message),
                'embed_time': embed_time,
                'extract_time': extract_time,
                'psnr': psnr,
                'mse': mse,
                'chi_square': chi_square_result['chi_square_statistic'],
                'chi_square_p_value': chi_square_result['p_value'],
                'correct_extraction': message == extracted,
                'status': 'SUCCESS'
            }
        except Exception as e:
            return {
                'method': 'traditional',
                'image': image_path,
                'message_length': len(message),
                'status': 'ERROR',
                'error': str(e)
            }

    def _test_enhanced(self, image_path, message, key):
        """Test enhanced LSB method"""
        try:
            original_img = np.array(Image.open(image_path))
            if len(original_img.shape) == 2 or original_img.shape[2] != 3:
                # Convert to RGB if needed
                img_pil = Image.open(image_path).convert('RGB')
                original_img = np.array(img_pil)

            start_time = time.time()
            stego_array = self.enhanced_lsb.embed_message(image_path, message, key)
            embed_time = time.time() - start_time

            if stego_array is None:
                return {
                    'method': 'enhanced',
                    'image': image_path,
                    'message_length': len(message),
                    'status': 'ERROR',
                    'error': 'Embedding failed'
                }

            # Save temporary for extraction
            temp_path = f"temp_{random.randint(1000, 9999)}.png"
            Image.fromarray(stego_array.astype(np.uint8)).save(temp_path)

            start_time = time.time()
            extracted = self.enhanced_lsb.extract_message(temp_path, key)
            extract_time = time.time() - start_time

            # Clean up
            try:
                os.remove(temp_path)
            except:
                pass

            psnr = self._calculate_psnr(original_img, stego_array)
            mse = self._calculate_mse(original_img, stego_array)

            # Security tests
            security_tester = SecurityTester(self.enhanced_lsb)
            chi_square_result = security_tester.chi_square_test(stego_array)

            return {
                'method': 'enhanced',
                'image': image_path,
                'message_length': len(message),
                'embed_time': embed_time,
                'extract_time': extract_time,
                'psnr': psnr,
                'mse': mse,
                'chi_square': chi_square_result['chi_square_statistic'],
                'chi_square_p_value': chi_square_result['p_value'],
                'correct_extraction': message == extracted if extracted else False,
                'status': 'SUCCESS'
            }
        except Exception as e:
            return {
                'method': 'enhanced',
                'image': image_path,
                'message_length': len(message),
                'status': 'ERROR',
                'error': str(e)
            }

    def _calculate_psnr(self, original, stego):
        """Calculate PSNR"""
        mse = np.mean((original.astype(float) - stego.astype(float)) ** 2)
        if mse == 0:
            return float('inf')
        return 20 * np.log10(255.0 / np.sqrt(mse))

    def _calculate_mse(self, original, stego):
        """Calculate MSE"""
        return np.mean((original.astype(float) - stego.astype(float)) ** 2)

    def _analyze_results(self, results):
        """Analyze and compare results"""
        analysis = {}

        for method in ['traditional', 'enhanced']:
            method_results = [r for r in results[method] if r['status'] == 'SUCCESS']

            if method_results:
                analysis[method] = {
                    'avg_psnr': np.mean([r['psnr'] for r in method_results]),
                    'avg_mse': np.mean([r['mse'] for r in method_results]),
                    'avg_embed_time': np.mean([r['embed_time'] for r in method_results]),
                    'avg_extract_time': np.mean([r['extract_time'] for r in method_results]),
                    'avg_chi_square': np.mean([r['chi_square'] for r in method_results]),
                    'avg_chi_square_p_value': np.mean([r['chi_square_p_value'] for r in method_results]),
                    'success_rate': np.mean([r['correct_extraction'] for r in method_results]),
                    'std_psnr': np.std([r['psnr'] for r in method_results]),
                    'total_tests': len(method_results)
                }
            else:
                analysis[method] = {
                    'avg_psnr': 0, 'avg_mse': 0, 'avg_embed_time': 0,
                    'avg_extract_time': 0, 'avg_chi_square': 0,
                    'avg_chi_square_p_value': 0, 'success_rate': 0,
                    'std_psnr': 0, 'total_tests': 0
                }

        # Calculate improvements
        improvements = {}
        if analysis['traditional']['total_tests'] > 0 and analysis['enhanced']['total_tests'] > 0:
            for metric in ['avg_psnr', 'avg_mse', 'avg_embed_time', 'avg_extract_time',
                           'avg_chi_square', 'success_rate']:
                traditional_val = analysis['traditional'][metric]
                enhanced_val = analysis['enhanced'][metric]

                if traditional_val != 0:
                    if metric in ['avg_chi_square', 'avg_embed_time', 'avg_extract_time', 'avg_mse']:
                        # Lower is better
                        improvement = ((traditional_val - enhanced_val) / traditional_val) * 100
                    else:
                        # Higher is better
                        improvement = ((enhanced_val - traditional_val) / traditional_val) * 100
                else:
                    improvement = 0

                improvements[metric] = improvement

        return {
            'detailed_analysis': analysis,
            'improvements': improvements,
            'raw_results': results
        }


def create_comparison_visualization(original, stego, message, output_path="comparison.png"):
    """Create side-by-side comparison visualization"""
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    # Original image
    axes[0].imshow(original)
    axes[0].set_title('Original Image')
    axes[0].axis('off')

    # Stego image
    axes[1].imshow(stego)
    axes[1].set_title('Stego Image')
    axes[1].axis('off')

    # Difference image (amplified)
    diff = np.abs(original.astype(float) - stego.astype(float))
    diff_amplified = np.clip(diff * 10, 0, 255)  # Amplify differences
    axes[2].imshow(diff_amplified.astype(np.uint8))
    axes[2].set_title('Difference (10x amplified)')
    axes[2].axis('off')

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.show()

    print(f"✓ Visualization saved as '{output_path}'")


def create_test_image(width=512, height=512, filename="test_image.png"):
    """Create a test image for demonstration"""
    # Create a simple test pattern
    image = np.zeros((height, width, 3), dtype=np.uint8)

    # Add some patterns for better testing
    for i in range(height):
        for j in range(width):
            image[i, j, 0] = (i + j) % 256  # Red channel
            image[i, j, 1] = (i * 2) % 256  # Green channel
            image[i, j, 2] = (j * 2) % 256  # Blue channel

    # Add some noise for realism
    noise = np.random.randint(-20, 21, (height, width, 3))
    image = np.clip(image.astype(int) + noise, 0, 255).astype(np.uint8)

    # Save the image
    Image.fromarray(image).save(filename)
    print(f"Test image created: {filename}")
    return filename


# Demo and testing functions
def main_demo():
    """Main demonstration of Enhanced LSB Steganography"""

    print("=" * 60)
    print("ENHANCED LSB STEGANOGRAPHY DEMONSTRATION")
    print("=" * 60)

    # Create or use test image
    image_path = create_test_image()

    # Initialize steganography engine
    engine = EnhancedLSBSteganography()

    # Test parameters
    secret_message = "This is a secret message hidden using enhanced LSB steganography with random pixel selection!"
    secret_key = "my_secret_key_2024"
    output_path = "stego_output.png"

    # Check capacity
    capacity_info = engine.get_embedding_capacity(image_path)
    print(f"Image Capacity Analysis:")
    print(f"  Image dimensions: {capacity_info['image_dimensions']}")
    print(f"  Maximum bits: {capacity_info['max_bits']:,}")
    print(f"  Maximum characters: {capacity_info['max_characters']:,}")
    print(f"  Overhead: {capacity_info['overhead_characters']} characters")
    print(f"  Message length: {len(secret_message)} characters")
    print(f"  Capacity utilization: {len(secret_message) / capacity_info['max_characters'] * 100:.2f}%")
    print()

    # Embedding process
    print("EMBEDDING PROCESS")
    print("-" * 20)
    original_img = np.array(Image.open(image_path))

    start_time = time.time()
    stego_array = engine.embed_message(image_path, secret_message, secret_key, output_path)
    embedding_time = time.time() - start_time

    if stego_array is not None:
        print(f"✓ Embedding successful in {embedding_time:.3f} seconds")

        # Calculate quality metrics
        psnr = engine.calculate_psnr(original_img, stego_array)
        mse = engine.calculate_mse(original_img, stego_array)

        print(f"  PSNR: {psnr:.2f} dB")
        print(f"  MSE: {mse:.4f}")
        print(f"  Quality: {'Excellent' if psnr > 50 else 'Good' if psnr > 40 else 'Acceptable'}")
    else:
        print("✗ Embedding failed")
        return

    print()

    # Extraction process
    print("EXTRACTION PROCESS")
    print("-" * 20)

    start_time = time.time()
    extracted_message = engine.extract_message(output_path, secret_key)
    extraction_time = time.time() - start_time

    if extracted_message is not None:
        print(f"✓ Extraction successful in {extraction_time:.3f} seconds")
        print(f"  Original message: '{secret_message}'")
        print(f"  Extracted message: '{extracted_message}'")
        print(f"  Messages match: {'Yes' if secret_message == extracted_message else 'No'}")
    else:
        print("✗ Extraction failed")
        return

    print()

    # Security testing
    print("SECURITY ANALYSIS")
    print("-" * 20)

    security_tester = SecurityTester(engine)

    # Chi-square test
    chi_square_result = security_tester.chi_square_test(stego_array)
    print(f"Chi-square Analysis:")
    print(f"  Chi-square statistic: {chi_square_result['chi_square_statistic']:.4f}")
    print(f"  P-value: {chi_square_result['p_value']:.6f}")
    print(f"  Suspicious: {'Yes' if chi_square_result['suspicious'] else 'No'}")

    # Histogram analysis
    hist_result = security_tester.histogram_analysis(original_img, stego_array)
    print(f"  Histogram correlation: {hist_result['histogram_correlation']:.6f}")

    # Brute force resistance (limited test)
    print(f"\nBrute Force Resistance Test (100 attempts):")
    bf_result = security_tester.brute_force_resistance_test(output_path, secret_key, 100)
    print(f"  Valid extractions: {bf_result['valid_extractions']}/100")
    print(f"  Resistance score: {bf_result['resistance_score']:.4f}")
    print(f"  Security level: {bf_result['security_level']}")

    print()

    # Visual comparison
    print("VISUAL COMPARISON")
    print("-" * 20)
    create_comparison_visualization(original_img, stego_array, secret_message)

    # Cleanup
    try:
        os.remove(image_path)
        print(f"Cleaned up test files")
    except:
        pass


def run_comparative_analysis():
    """Run comparative analysis between traditional and enhanced methods"""
    print("\n" + "=" * 80)
    print("COMPARATIVE ANALYSIS: TRADITIONAL vs ENHANCED LSB")
    print("=" * 80)

    # Create test images
    test_images = []
    for i, size in enumerate([(256, 256), (512, 512)]):
        filename = create_test_image(size[0], size[1], f"test_{size[0]}x{size[1]}.png")
        test_images.append(filename)

    test_messages = [
        "Short message",
        "Medium length message for testing purposes.",
        "This is a longer message that will test the capacity and performance of both methods more thoroughly."
    ]

    analyzer = ComparativeAnalysis()
    results = analyzer.comprehensive_comparison(test_images, test_messages)

    # Print results
    print(f"\nTraditional LSB Performance:")
    trad_analysis = results['detailed_analysis']['traditional']
    print(f"  Tests completed: {trad_analysis['total_tests']}")
    print(f"  Average PSNR: {trad_analysis['avg_psnr']:.2f} dB")
    print(f"  Average MSE: {trad_analysis['avg_mse']:.4f}")
    print(f"  Average Chi-square: {trad_analysis['avg_chi_square']:.2f}")
    print(f"  Success rate: {trad_analysis['success_rate'] * 100:.1f}%")

    print(f"\nEnhanced LSB Performance:")
    enh_analysis = results['detailed_analysis']['enhanced']
    print(f"  Tests completed: {enh_analysis['total_tests']}")
    print(f"  Average PSNR: {enh_analysis['avg_psnr']:.2f} dB")
    print(f"  Average MSE: {enh_analysis['avg_mse']:.4f}")
    print(f"  Average Chi-square: {enh_analysis['avg_chi_square']:.2f}")
    print(f"  Success rate: {enh_analysis['success_rate'] * 100:.1f}%")

    print(f"\nImprovements (Enhanced vs Traditional):")
    for metric, improvement in results['improvements'].items():
        print(f"  {metric}: {improvement:+.1f}%")

    # Cleanup test images
    for img_path in test_images:
        try:
            os.remove(img_path)
        except:
            pass


if __name__ == "__main__":
    # Run main demonstration
    main_demo()

    # Run comparative analysis
    run_comparative_analysis()

    print("\n" + "=" * 60)
    print("DEMONSTRATION COMPLETED")
    print("=" * 60)