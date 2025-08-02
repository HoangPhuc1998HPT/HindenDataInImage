from enhanced_lsb_steganography import *


def simple_usage_example():
    """Simple usage example"""

    # Initialize the steganography engine
    stego = EnhancedLSBSteganography()

    # Create a test image
    test_image = create_test_image(512, 512, "my_test_image.png")

    # Your secret message and key
    message = "Hello, this is my secret message!"
    key = "my_secret_password"

    print("=== SIMPLE USAGE EXAMPLE ===")

    # Embed message
    print("1. Embedding message...")
    stego_image = stego.embed_message(test_image, message, key, "output_stego.png")

    if stego_image is not None:
        print("   ✓ Message embedded successfully!")

        # Extract message
        print("2. Extracting message...")
        extracted = stego.extract_message("output_stego.png", key)

        if extracted == message:
            print("   ✓ Message extracted successfully!")
            print(f"   Original: '{message}'")
            print(f"   Extracted: '{extracted}'")
        else:
            print("   ✗ Extraction failed or message corrupted")
    else:
        print("   ✗ Embedding failed")

    # Cleanup
    try:
        os.remove(test_image)
        os.remove("output_stego.png")
    except:
        pass


def advanced_usage_example():
    """Advanced usage with security testing"""

    stego = EnhancedLSBSteganography()
    security_tester = SecurityTester(stego)

    print("\n=== ADVANCED USAGE WITH SECURITY TESTING ===")

    # Create test setup
    test_image = create_test_image(256, 256, "advanced_test.png")
    message = "Advanced steganography test with security analysis."
    key = "advanced_key_2024"

    # Load original image
    original = np.array(Image.open(test_image))

    # Embed with enhanced method
    stego_array = stego.embed_message(test_image, message, key, "advanced_stego.png")

    if stego_array is not None:
        # Quality analysis
        psnr = stego.calculate_psnr(original, stego_array)
        mse = stego.calculate_mse(original, stego_array)

        print(f"Quality Metrics:")
        print(f"  PSNR: {psnr:.2f} dB")
        print(f"  MSE: {mse:.4f}")

        # Security analysis
        chi_square = security_tester.chi_square_test(stego_array)
        histogram = security_tester.histogram_analysis(original, stego_array)

        print(f"Security Analysis:")
        print(f"  Chi-square p-value: {chi_square['p_value']:.6f}")
        print(f"  Suspicious: {chi_square['suspicious']}")
        print(f"  Histogram correlation: {histogram['histogram_correlation']:.6f}")

        # Test wrong key
        wrong_extracted = stego.extract_message("advanced_stego.png", "wrong_key")
        print(f"Wrong key test: {'PASS' if wrong_extracted != message else 'FAIL'}")

    # Cleanup
    try:
        os.remove(test_image)
        os.remove("advanced_stego.png")
    except:
        pass


def batch_processing_example():
    """Example of processing multiple images"""

    print("\n=== BATCH PROCESSING EXAMPLE ===")

    stego = EnhancedLSBSteganography()

    # Create multiple test images
    test_data = [
        {"size": (128, 128), "message": "Small image test", "key": "key1"},
        {"size": (256, 256), "message": "Medium image test", "key": "key2"},
        {"size": (512, 512), "message": "Large image test", "key": "key3"}
    ]

    results = []

    for i, data in enumerate(test_data):
        print(f"Processing image {i + 1}/{len(test_data)}...")

        # Create test image
        img_path = f"batch_test_{i}.png"
        create_test_image(data["size"][0], data["size"][1], img_path)

        # Process
        start_time = time.time()
        stego_array = stego.embed_message(img_path, data["message"], data["key"])
        embed_time = time.time() - start_time

        if stego_array is not None:
            # Save stego image
            stego_path = f"batch_stego_{i}.png"
            Image.fromarray(stego_array.astype(np.uint8)).save(stego_path)

            # Extract and verify
            start_time = time.time()
            extracted = stego.extract_message(stego_path, data["key"])
            extract_time = time.time() - start_time

            # Calculate quality
            original = np.array(Image.open(img_path))
            psnr = stego.calculate_psnr(original, stego_array)

            results.append({
                'image_size': data["size"],
                'message_length': len(data["message"]),
                'embed_time': embed_time,
                'extract_time': extract_time,
                'psnr': psnr,
                'success': extracted == data["message"]
            })

            # Cleanup
            try:
                os.remove(img_path)
                os.remove(stego_path)
            except:
                pass
        else:
            results.append({
                'image_size': data["size"],
                'success': False,
                'error': 'Embedding failed'
            })

    # Print summary
    print(f"\nBatch Processing Results:")
    for i, result in enumerate(results):
        if result['success']:
            print(f"  Image {i + 1}: ✓ PSNR={result['psnr']:.1f}dB, Time={result['embed_time']:.3f}s")
        else:
            print(f"  Image {i + 1}: ✗ Failed")


if __name__ == "__main__":
    simple_usage_example()
    advanced_usage_example()
    batch_processing_example()